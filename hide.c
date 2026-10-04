/*
 * hide.so — user-space file hiding, bind-style redirection and /proc sanitization
 *          for Android (bionic), via LD_PRELOAD.
 *
 * Copyright (C) 2026 null07089
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 * This program is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this
 * program. If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/stat.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <utime.h>
#include <unistd.h>

/* 全部配置仅来自运行时环境变量（无编译期默认）：
   HIDE_FILES="/a/b/name[:/c/d ...]"   隐藏名单。只支持绝对路径：
       命中该路径即隐藏；目录命中则连同其整个子树一起隐藏。
       非绝对路径条目会被忽略并打印告警（请自行展开为绝对路径）。
   REDIRECT_FILES="src=dst[:src2=dst2...]"  文件重定向（用户态 bind mount）
       命中后读写/stat/open/getxattr 等透明改写：src 为文件精确替换，为目录前缀替换；
       扩展属性同样改写，故 SELinux 标签（security.selinux）随重定向变为 dst 的标签；
       execve 同样参与重定向：命中 src 时路径会被改写为 dst。
       优先级：本次操作命中重定向时跳过 HIDE_FILES 判定——即便 dst 本身在隐藏名单中，
       经 src 访问仍可达（视为“dst 是本次重定向的目标”）；直接访问 dst（未重定向）
       仍照常隐藏。
   SKIP_RESTRICTED_PATHS="/vendor:/odm:..."  跳过注入的路径前缀（冒号分隔）：
        该路径下的程序执行前剥离全部配置残留、不注入 LD_PRELOAD（同静态程序处理）。
   HIDE_SO="libfoo.so:/path/libbar.so"  隐藏 /proc/<pid>/{maps,smaps,smaps_rollup}
       中含该匹配项的行；并隐藏 /proc/<pid>/map_files 下指向这些库的符号链接。
       含 '/' 的路径项会先 realpath 绝对化；并始终自动加入 LD_PRELOAD 自身。
   HIDE_MOUNT="/data:/mnt/secret"  隐藏挂载点：
        过滤 /proc/<pid>/{mounts,mountinfo,mountstat[s]} 中等于该路径或位于其下的行；
        statfs/statvfs 视为不存在；umount/umount2 返回 EINVAL。
        （不影响目录列举：readdir/scandir 仍会列出该挂载点。）
   ALLOW_ACCESS="/a/b/name[:/c/d...]"  放行名单（绝对路径，冒号分隔）：
        只作用于 fstatat/fstatat64/faccessat 探测与 execve；其余钩子不受影响。
        fstatat/faccessat：命中重定向时跳过隐藏；否则对字面路径判定，
        命中名单才豁免 HIDE_FILES。
        execve 例外：命中 ALLOW 时走字面原路径、不重定向且不隐藏。
        目录条目对整棵子树生效。
        bionic 无 newfstatat 符号，其语义即 fstatat/fstatat64。
    HIDE_FILES 中命中但不在 ALLOW_ACCESS 的文件不允许被 execve 执行（ENOENT）。
    以上所有变量一旦设置都会被彻底隐藏（env/getenv/printenv/echo、/proc/<pid>/environ），
    动态子进程回注以继承配置，静态目标及 SKIP_RESTRICTED_PATHS 命中目标剥离。
    注：/proc/<pid>/{mem,pagemap} 是二进制、不含路径，无法做路径隐藏。
*/

/* 需要精确匹配/隐藏的 LD_PRELOAD 值：直接取当前 LD_PRELOAD（绕过本库 getenv 钩子）。 */
static char *g_ld_value;   /* 精确匹配值（运行时） */
static size_t g_ld_vlen;
static char *g_ld_entry;   /* "LD_PRELOAD=<value>"（运行时构造） */

extern char **environ;

/* 原地（in-place）从 environ 数组移除某变量：移位后末尾置 NULL。
   这样 main 拿到的 envp 数组（bionic 下与 environ 同一块内存）也被清理，
   env/printenv/echo $VAR 与子进程都看不到。注意不能用 unsetenv：
   它可能把 environ 换成新数组，而 main 仍指向旧数组（bash 正是从旧数组导入变量）。 */
static void env_remove_inplace(const char *name)
{
    size_t nl = strlen(name);
    int w = 0;
    for (int r = 0; environ && environ[r]; r++) {
        if (strncmp(environ[r], name, nl) == 0 && environ[r][nl] == '=') continue;
        environ[w++] = environ[r];
    }
    if (environ) environ[w] = NULL;
}

static char *make_env_entry(const char *name, const char *val)
{
    size_t nl = strlen(name), vl = strlen(val);
    char *s = malloc(nl + 1 + vl + 1);
    if (!s) return NULL;
    memcpy(s, name, nl);
    s[nl] = '=';
    memcpy(s + nl + 1, val, vl + 1);
    return s;
}

/* 构造期直接扫描 environ 读取配置值：不经 dlsym(getenv)、不依赖 libc，必然可见，
   也绝不会因 dlsym 失败而漏掉“解析+移除”导致配置泄露。 */
static const char *raw_getenv(const char *name)
{
    size_t nl = strlen(name);
    for (int i = 0; environ && environ[i]; i++)
        if (strncmp(environ[i], name, nl) == 0 && environ[i][nl] == '=')
            return environ[i] + nl + 1;
    return NULL;
}

/* ---------- 运行时配置变量：名称/长度集中定义，供解析、脱敏、回注复用 ---------- */

enum {
    CFG_LD = 0,   /* LD_PRELOAD */
    CFG_HIDE,     /* HIDE_FILES */
    CFG_REDIR,    /* REDIRECT_FILES */
    CFG_SKIPRP,   /* SKIP_RESTRICTED_PATHS */
    CFG_SO,       /* HIDE_SO */
    CFG_MOUNT,    /* HIDE_MOUNT */
    CFG_ALLOW,    /* ALLOW_ACCESS */
    CFG_N
};

#define CFG_ENT(n) { n, sizeof(n) - 1 }

static const struct { const char *name; size_t len; } cfg_vars[CFG_N] = {
    [CFG_LD]     = CFG_ENT("LD_PRELOAD"),
    [CFG_HIDE]   = CFG_ENT("HIDE_FILES"),
    [CFG_REDIR]  = CFG_ENT("REDIRECT_FILES"),
    [CFG_SKIPRP] = CFG_ENT("SKIP_RESTRICTED_PATHS"),
    [CFG_SO]     = CFG_ENT("HIDE_SO"),
    [CFG_MOUNT]  = CFG_ENT("HIDE_MOUNT"),
    [CFG_ALLOW]  = CFG_ENT("ALLOW_ACCESS"),
};

/* 构造期保存、供 execve 回注的 "NAME=value"（NULL 表示无需回注），下标同 cfg_vars */
static char *inject_entries[CFG_N];

/* 运行期用户/程序主动改过 LD_PRELOAD（setenv/putenv/unsetenv）后置位：
   此后不再剥离/回注 LD_PRELOAD，尊重其设置，避免“我设了却不生效”引起排查而暴露。 */
static int ld_preload_user_set;

/* ---------- 隐藏名单（仅绝对路径） ---------- */

#define MAXHIDE 64

/* 路径条目：预计算绝对路径与长度，热路径字符串匹配直接复用 */
typedef struct {
    char *abs;         /* 规范化后的绝对路径 */
    size_t abslen;
    int is_dir;
} pitem;

static pitem pitems[MAXHIDE];
static int npitems;

/* 独立的 inode 身份表（dev+ino）：与 pitems 排序解耦，ino_exact/entry_hidden
   只需遍历有身份的条目，避免每条都判 has_ident。 */
static dev_t ident_dev[MAXHIDE];   /* 绑定挂载别名（/data/data <-> /data/user/0）*/
static ino_t ident_ino[MAXHIDE];
static int nident;
static int has_ident;       /* nident > 0 */
static int has_dir_ident;   /* 存在带身份的目录条目 */

/* 防止初始化阶段 libc realpath 内部触发 readlink/stat 钩子造成重入 */
static __thread int in_hook;
static char *(*g_real_realpath)(const char *, char *);

/* 直连 fstatat 系统调用取真实 stat。
   不能 dlsym 找 libc stat：libc 内部会经 PLT 调 fstatat64，
   被本库钩子拦截造成死递归（stat/lstat/fstatat 在 bionic 里是别名）。 */
static int real_stat(const char *path, struct stat *buf)
{
#ifdef __NR_newfstatat
    return syscall(__NR_newfstatat, AT_FDCWD, path, buf, 0);
#else
    return syscall(SYS_fstatat, AT_FDCWD, path, buf, 0);
#endif
}

/* ---------- 低层 syscall（绕过本库钩子） ---------- */

static int raw_open_ro(const char *path)
{
#ifdef __NR_openat
    return (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
#else
    return (int)syscall(SYS_open, path, O_RDONLY | O_CLOEXEC);
#endif
}

static ssize_t raw_read(int fd, void *buf, size_t n)
{
#ifdef __NR_read
    return syscall(__NR_read, fd, buf, n);
#else
    return read(fd, buf, n);
#endif
}

static off_t raw_seek(int fd, off_t off)
{
#ifdef __NR_lseek
    return (off_t)syscall(__NR_lseek, fd, off, SEEK_SET);
#else
    return lseek(fd, off, SEEK_SET);
#endif
}

static ssize_t raw_write(int fd, const void *buf, size_t n)
{
#ifdef __NR_write
    return syscall(__NR_write, fd, buf, n);
#else
    return write(fd, buf, n);
#endif
}

static int raw_memfd(const char *name, unsigned int flags)
{
#ifdef __NR_memfd_create
    return (int)syscall(__NR_memfd_create, name, flags);
#else
    (void)name; (void)flags; errno = ENOSYS; return -1;
#endif
}

static int write_all(int fd, const char *p, size_t n)
{
    size_t w = 0;
    while (w < n) {
        ssize_t r = raw_write(fd, p + w, n - w);
        if (r <= 0) return -1;
        w += (size_t)r;
    }
    return 0;
}

/* 词法转绝对路径并折叠 . / ..，写进调用方缓冲。
   不解析符号链接：别名由 inode 身份匹配兜底，从而彻底避开 realpath 的逐级系统调用。
   仅相对路径需要一次 getcwd。 */
static int lex_abs(const char *path, char *buf, size_t bufsz)
{
    size_t pl = strlen(path);
    /* 快路径：绝对路径且不含 . / .. 分量、无重复/尾随斜杠时天然干净，直接拷贝。
       只检测真正的点分量，含扩展名/点文件的路径也走此快路径。 */
    if (path[0] == '/' && pl > 1 && path[pl - 1] != '/' &&
        pl + 1 <= bufsz && !strstr(path, "//") &&
        !strstr(path, "/./") && !strstr(path, "/..") &&
        !(path[pl - 1] == '.' && path[pl - 2] == '/')) {
        memcpy(buf, path, pl + 1);
        return 1;
    }

    size_t pos = 0;
    if (path[0] != '/') {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof cwd)) return 0;
        size_t l = strlen(cwd);
        if (l + 1 >= bufsz) return 0;
        memcpy(buf, cwd, l);
        pos = l;
    }
    const char *p = path;
    while (*p) {
        if (*p == '/') { p++; continue; }
        const char *end = strchr(p, '/');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == 1 && p[0] == '.') {
            /* skip */
        } else if (len == 2 && p[0] == '.' && p[1] == '.') {
            if (pos > 0 && buf[pos - 1] == '/') pos--;
            while (pos > 0 && buf[pos - 1] != '/') pos--;
            if (pos == 0) buf[pos++] = '/';
        } else {
            if (pos == 0 || buf[pos - 1] != '/') {
                if (pos + 1 >= bufsz) return 0;
                buf[pos++] = '/';
            }
            if (pos + len >= bufsz) return 0;
            memcpy(buf + pos, p, len);
            pos += len;
        }
        if (!end) break;
        p = end + 1;
    }
    if (pos == 0) {
        if (bufsz < 2) return 0;
        buf[pos++] = '/';
    }
    buf[pos] = '\0';
    return 1;
}

/* 调用 libc 的 realpath（RTLD_NEXT，避开本库钩子），带重入保护。
   real 指针用 pthread_once 一次性解析，避免多线程懒加载竞争。 */
static void load_real_realpath(void)
{
    g_real_realpath = dlsym(RTLD_NEXT, "realpath");
}
static pthread_once_t rp_once = PTHREAD_ONCE_INIT;

static char *canon_path(const char *in, char *out)
{
    if (in_hook) return NULL;
    in_hook = 1; /* 覆盖 pthread_once：若 dlsym 内部回调本库钩子，直接短路防自锁 */
    pthread_once(&rp_once, load_real_realpath);
    char *r = g_real_realpath ? g_real_realpath(in, out) : NULL;
    in_hook = 0;
    return r;
}

/* 词法规范化：转绝对路径、去掉 . 和 ..；若路径存在再用 libc realpath 解析符号链接
   （/data/user/0 -> /data/data 等）。仅一次分配。 */
static char *normalize(const char *path)
{
    if (!path) return NULL;
    char buf[PATH_MAX];
    if (!lex_abs(path, buf, sizeof buf)) return NULL;
    char rbuf[PATH_MAX];
    char *canon = canon_path(buf, rbuf);
    return strdup(canon ? canon : buf);
}

/* 只接受绝对路径：目录/文件按规范化绝对路径 + inode 身份登记 */
static void add_item(const char *tok)
{
    if (!tok || !*tok) return;
    if (tok[0] != '/') {
        dprintf(2, "hide.so: HIDE_FILES '%s' ignored (absolute paths only)\n", tok);
        return;
    }
    if (npitems >= MAXHIDE) return;
    char *abs = normalize(tok);
    if (!abs) return;
    pitem *it = &pitems[npitems++];
    it->abs = abs;
    it->abslen = strlen(abs);
    it->is_dir = 0;
    struct stat sb;
    if (real_stat(abs, &sb) == 0) {
        it->is_dir = S_ISDIR(sb.st_mode);
        ident_dev[nident] = sb.st_dev;
        ident_ino[nident] = sb.st_ino;
        nident++;
        has_ident = 1;
        if (it->is_dir) has_dir_ident = 1;
    }
}

/* ---------- 放行名单 ALLOW_ACCESS（仅绝对路径） ----------
   名单内路径：fstatat/fstatat64/faccessat 探测放行，且 execve 允许执行；
   其余钩子照常完全隐藏。 */

#define MAXALLOW 64

static char *aitems[MAXALLOW];
static size_t aitem_len[MAXALLOW];
static int naitems;

static void add_allow(const char *tok)
{
    if (!tok || !*tok) return;
    if (tok[0] != '/') {
        dprintf(2, "hide.so: ALLOW_ACCESS '%s' ignored (absolute paths only)\n", tok);
        return;
    }
    if (naitems >= MAXALLOW) return;
    char *abs = normalize(tok);
    if (!abs) return;
    aitems[naitems] = abs;
    aitem_len[naitems] = strlen(abs);
    naitems++;
}

/* ---------- 文件重定向（用户态 bind mount） ----------
   配置 REDIRECT_FILES="src=dst[:src2=dst2...]"（冒号分隔，首个 '=' 分割）。
   命中后所有路径类系统调用的路径参数被改写：src 为文件则精确替换，为目录则前缀替换。 */

#define MAXREDIR 32

typedef struct {
    char *src;
    size_t srclen;
    char *dst;
    size_t dstlen;
    int is_dir;
} ritem;

static ritem ritems[MAXREDIR];
static int nritems;

/* 把 path 解析为词法绝对路径写入 out：绝对路径直接词法化；相对路径且 dirfd
   非 AT_FDCWD 时，先经 /proc/self/fd/<dirfd> 取目录再拼接（与内核 dirfd 语义一致）。
   供重定向、隐藏/放行匹配、/proc 识别共用，避免各处重复解析逻辑。 */
static int resolve_at(int dirfd, const char *path, char *out, size_t outsz)
{
    if (path[0] == '/' || dirfd == AT_FDCWD)
        return lex_abs(path, out, outsz);

    char link[64], base[PATH_MAX], joined[PATH_MAX];
    int ln = snprintf(link, sizeof link, "/proc/self/fd/%d", dirfd);
    if (ln <= 0 || ln >= (int)sizeof link) return 0;
    ssize_t n = syscall(__NR_readlinkat, AT_FDCWD, link, base, sizeof base - 1);
    if (n <= 0 || (size_t)n >= sizeof base - 1) return 0;
    base[n] = '\0';
    if (snprintf(joined, sizeof joined, "%s/%s", base, path) >= (int)sizeof joined) return 0;
    return lex_abs(joined, out, outsz);
}

/* 命中重定向则把结果写入调用方缓冲 out（大小 outsz），返回 1；否则 0。
   不返回内部静态/TLS 缓冲，避免多路径改写互相覆盖与重入覆盖。 */
static int redirect_into(int dirfd, const char *path, char *out, size_t outsz)
{
    if (!nritems || !path || !*path) return 0;

    char abs[PATH_MAX];
    if (!resolve_at(dirfd, path, abs, sizeof abs)) return 0;

    size_t al = strlen(abs);
    for (int i = 0; i < nritems; i++) {
        ritem *r = &ritems[i];
        if (al == r->srclen && memcmp(abs, r->src, r->srclen) == 0) {
            if (r->dstlen + 1 > outsz) return 0;
            memcpy(out, r->dst, r->dstlen + 1);
            return 1;
        }
        if (r->is_dir && al > r->srclen &&
            memcmp(abs, r->src, r->srclen) == 0 && abs[r->srclen] == '/') {
            size_t rem = al - r->srclen; /* 含前导 '/' */
            if (r->dstlen + rem + 1 > outsz) return 0;
            memcpy(out, r->dst, r->dstlen);
            memcpy(out + r->dstlen, abs + r->srclen, rem + 1);
            return 1;
        }
    }
    return 0;
}

static void add_redirect(const char *tok)
{
    if (nritems >= MAXREDIR || !tok || !*tok) return;
    const char *eq = strchr(tok, '=');
    if (!eq || eq == tok || !eq[1]) {
        dprintf(2, "hide.so: REDIRECT_FILES bad entry '%s' (want src=dst)\n", tok);
        return;
    }
    size_t sl = (size_t)(eq - tok);
    char *src = malloc(sl + 1);
    if (!src) return;
    memcpy(src, tok, sl);
    src[sl] = '\0';
    char *s = normalize(src);
    char *d = normalize(eq + 1);
    free(src);
    if (!s || !d) { free(s); free(d); return; }
    ritem *r = &ritems[nritems++];
    r->src = s;
    r->srclen = strlen(s);
    r->dst = d;
    r->dstlen = strlen(d);
    struct stat sb;
    r->is_dir = (real_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode));
}

/* 重定向目标标记（TLS）：本次操作命中重定向后，libc 内部可能再次回调本库钩子
   （如 stat -> fstatat、realpath -> lstat），这些嵌套调用作用于重定向后的路径，
   应同样跳过 HIDE 判定。用“深度 + 目标路径”标记，配合 REDIR_SCOPE 在钩子返回时
   自动回退（含早退、多重路径），从而只豁免本次操作、不影响之后的直接访问。 */
static __thread char tls_redir_dst[PATH_MAX];
static __thread int tls_redir_depth;
static __thread int tls_redir_ident;   /* 目标 inode 身份有效 */
static __thread dev_t tls_redir_dev;
static __thread ino_t tls_redir_ino;

static void redir_scope_restore(int *saved)
{
    while (tls_redir_depth > *saved && tls_redir_depth > 0) {
        if (--tls_redir_depth == 0) { tls_redir_dst[0] = '\0'; tls_redir_ident = 0; }
    }
}

/* 某 dev/ino 是否即本次重定向目标（用于别名路径，如 /proc/self/fd/N）。 */
static int redir_ident_match(dev_t dev, ino_t ino)
{
    return tls_redir_depth > 0 && tls_redir_ident &&
           dev == tls_redir_dev && ino == tls_redir_ino;
}
/* 在每个路径钩子入口声明一次：返回时自动把深度回退到进入时的值。 */
#define REDIR_SCOPE() \
    int __redir_saved __attribute__((cleanup(redir_scope_restore))) = tls_redir_depth

/* 命中重定向则改写 *pathp 到 buf、标记目标路径并返回 1；未命中返回 0。 */
static int redirect_at(int dirfd, const char **pathp, char *buf)
{
    if (!nritems || !*pathp || !**pathp) return 0;
    if (!redirect_into(dirfd, *pathp, buf, PATH_MAX)) return 0;
    *pathp = buf;
    size_t l = strlen(buf);
    if (l < sizeof tls_redir_dst) {
        memcpy(tls_redir_dst, buf, l + 1);
        struct stat sb;
        tls_redir_ident = (real_stat(buf, &sb) == 0);
        if (tls_redir_ident) { tls_redir_dev = sb.st_dev; tls_redir_ino = sb.st_ino; }
        tls_redir_depth++;
    }
    return 1;
}

/* 当前是否正处于某次重定向操作，且 path 恰为该次重定向的目标。 */
static int redir_target(const char *path)
{
    return path && tls_redir_depth > 0 && strcmp(path, tls_redir_dst) == 0;
}

/* 命中重定向则把局部 path 指向栈上 alloca 缓冲（生命周期到本函数返回），
   并返回 1；未命中返回 0。返回值为 1 时调用方应跳过 HIDE 判定。 */
#define REDIR(path) __extension__({ \
    int __r = 0; \
    if (nritems) { \
        char *__rb = (char *)__builtin_alloca(PATH_MAX); \
        if (redirect_at(AT_FDCWD, &(path), __rb)) __r = 1; \
    } \
    __r; \
})
#define REDIR_AT(dirfd, path) __extension__({ \
    int __r = 0; \
    if (nritems) { \
        char *__rb = (char *)__builtin_alloca(PATH_MAX); \
        if (redirect_at((dirfd), &(path), __rb)) __r = 1; \
    } \
    __r; \
})

/* ---------- SKIP_RESTRICTED_PATHS：命中路径不注入 LD_PRELOAD ---------- */

#define MAXRPRE 32

static char *skip_pref[MAXRPRE];
static int nskip_pref;

static void add_skip_prefix(const char *tok)
{
    if (nskip_pref >= MAXRPRE || !tok || !*tok) return;
    size_t l = strlen(tok);
    while (l > 1 && tok[l - 1] == '/') l--; /* 去掉末尾 '/'，比较时按边界处理 */
    if (l == 0) return;
    char *s = malloc(l + 1);
    if (!s) return;
    memcpy(s, tok, l);
    s[l] = '\0';
    skip_pref[nskip_pref++] = s;
}

/* ---------- HIDE_SO / HIDE_MOUNT：/proc 文本文件行过滤 ---------- */

#define MAXTOK 64

static char *so_tokens[MAXTOK];
static size_t so_token_len[MAXTOK];
static int nso;

static char *mnt_tokens[MAXTOK];
static size_t mnt_token_len[MAXTOK];
static int nmnt;

/* 把冒号分隔的存储串就地切分，逐个交给回调（空项跳过） */
static void split_colon(char *storage, void (*cb)(const char *))
{
    if (!storage) return;
    char *p = storage, *start = storage;
    while (*p) {
        if (*p == ':') {
            *p = '\0';
            if (*start) cb(start);
            start = p + 1;
        }
        p++;
    }
    if (*start) cb(start);
}

static int token_exists(char *const *arr, const size_t *lens, int n, const char *tok, size_t l)
{
    for (int i = 0; i < n; i++)
        if (lens[i] == l && memcmp(arr[i], tok, l) == 0) return 1;
    return 0;
}

/* 加入一个 HIDE_SO 匹配项：含 '/' 的路径先 realpath 绝对化，
   以匹配 /proc/<pid>/maps 中显示的绝对库路径；裸名按原样（边界匹配）。 */
static void add_so_token(const char *tok)
{
    if (nso >= MAXTOK || !tok || !*tok) return;
    char *v;
    if (strchr(tok, '/')) {
        char *abs = normalize(tok);      /* 存在则 realpath，否则词法绝对化 */
        v = abs ? abs : strdup(tok);
    } else {
        v = strdup(tok);
    }
    if (!v) return;
    size_t l = strlen(v);
    if (token_exists(so_tokens, so_token_len, nso, v, l)) { free(v); return; }
    so_tokens[nso] = v;
    so_token_len[nso] = l;
    nso++;
}

/* 加入一个 HIDE_MOUNT 挂载点：词法绝对化后去重登记。
   仅做词法绝对化（不 realpath），以匹配 /proc mounts 中内核记录的文本路径。 */
static void add_mount_token(const char *tok)
{
    if (nmnt >= MAXTOK || !tok || !*tok) return;
    char buf[PATH_MAX];
    if (!lex_abs(tok, buf, sizeof buf)) return;
    size_t l = strlen(buf);
    if (token_exists(mnt_tokens, mnt_token_len, nmnt, buf, l)) return;
    char *s = malloc(l + 1);
    if (!s) return;
    memcpy(s, buf, l + 1);
    mnt_tokens[nmnt] = s;
    mnt_token_len[nmnt] = l;
    nmnt++;
}

/* 解析 LD_PRELOAD 值（可含多个、以 ':' 或空白分隔），逐个绝对化后加入 HIDE_SO。
   这样无需用户额外配置即可固定隐藏 hide.so 自身。 */
static void add_preload_so_tokens(const char *v)
{
    if (!v || !*v) return;
    char *storage = strdup(v);
    if (!storage) return;
    char *p = storage;
    while (*p) {
        while (*p == ':' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        char *start = p;
        while (*p && *p != ':' && *p != ' ' && *p != '\t') p++;
        char save = *p;
        *p = '\0';
        add_so_token(start);
        if (!save) break;
        p++;
    }
    free(storage);
}

/* ---------- 构造：解析并隐藏全部配置 ---------- */

/* abs_str_match 依赖 abslen 升序以提前退出，构造末尾统一排序 */
static int cmp_pitem(const void *a, const void *b)
{
    size_t la = ((const pitem *)a)->abslen, lb = ((const pitem *)b)->abslen;
    return (la > lb) - (la < lb);
}

/* 读取一个“冒号分隔”的配置变量：strdup 后交 split_colon（就地切分）解析，
   随后构造回注条目并从 environ 中彻底移除。解析失败也保持移除，避免泄露。 */
static void load_cfg(const char *name, void (*cb)(const char *), int slot)
{
    const char *v = raw_getenv(name);
    if (!v || !*v) return;
    char *storage = strdup(v);
    if (storage) {
        split_colon(storage, cb);
        free(storage);
    }
    if (slot >= 0) inject_entries[slot] = make_env_entry(name, v);
    env_remove_inplace(name);
}

__attribute__((constructor)) static void init_hidden(void)
{
    load_cfg("HIDE_FILES", add_item, CFG_HIDE);
    load_cfg("ALLOW_ACCESS", add_allow, CFG_ALLOW);
    load_cfg("REDIRECT_FILES", add_redirect, CFG_REDIR);
    load_cfg("SKIP_RESTRICTED_PATHS", add_skip_prefix, CFG_SKIPRP);
    load_cfg("HIDE_SO", add_so_token, CFG_SO);
    load_cfg("HIDE_MOUNT", add_mount_token, CFG_MOUNT);

    /* LD_PRELOAD 精确匹配值直接扫描 environ 取得（绕过本库 getenv 钩子） */
    const char *lp = raw_getenv("LD_PRELOAD");
    if (lp && *lp) {
        g_ld_value = strdup(lp);
        if (g_ld_value) {
            g_ld_vlen = strlen(g_ld_value);
            g_ld_entry = make_env_entry("LD_PRELOAD", g_ld_value);
        }
        /* 固定隐藏 LD_PRELOAD 自身：解析为绝对路径加入 HIDE_SO */
        add_preload_so_tokens(lp);
        /* LD_PRELOAD 仅当值等于匹配目标时删；删前保存供动态子进程回注 */
        if (g_ld_value && strcmp(lp, g_ld_value) == 0) {
            inject_entries[CFG_LD] = make_env_entry("LD_PRELOAD", lp);
            env_remove_inplace("LD_PRELOAD");
        }
    }

    /* abslen 升序：前缀匹配时遇 abslen > 目标长度即可停止扫描 */
    if (npitems > 1) qsort(pitems, (size_t)npitems, sizeof pitems[0], cmp_pitem);
}

/* ---------- 匹配核心：字符串 -> 一次 stat 的 inode 精确匹配 -> 带回溯缓存的祖先检查 ---------- */

/* 纯字符串精确/前缀匹配（无系统调用）。
   pitems 已按 abslen 升序：一旦 abslen > nlen 就不可能再命中，直接停止。 */
static int abs_str_match(const char *norm, size_t nlen)
{
    for (int i = 0; i < npitems; i++) {
        const pitem *it = &pitems[i];
        if (it->abslen > nlen) break;
        if (memcmp(norm, it->abs, it->abslen) == 0 &&
            (it->abslen == nlen || norm[it->abslen] == '/'))
            return 1;
    }
    return 0;
}

/* inode 精确匹配（dev+ino） */
static int ino_exact(dev_t dev, ino_t ino)
{
    for (int i = 0; i < nident; i++)
        if (dev == ident_dev[i] && ino == ident_ino[i]) return 1;
    return 0;
}

/* 线程内“干净目录”缓存：某个祖先目录一旦确认不含（也不位于）隐藏目录，
   其后代都干净，回溯可立即停止，避免重复 stat。 */
#define DCACHE 128
static __thread char *clean_dirs[DCACHE];

static unsigned dhash(const char *s)
{
    unsigned h = 2166136261u;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 16777619u;
    return h;
}

/* 检查并接管一个待缓存的干净目录路径（已 strdup） */
static void clean_put_owned(char *p)
{
    unsigned i = dhash(p) & (DCACHE - 1);
    free(clean_dirs[i]);
    clean_dirs[i] = p;
}

/* norm 是否位于某个隐藏目录之内：逐级向上，带线程内“干净目录”缓存 */
static int ancestor_hidden(const char *norm)
{
    if (!has_dir_ident) return 0;
    size_t nlen = strlen(norm);
    char tmp[PATH_MAX];
    if (nlen >= sizeof tmp) return 0;
    memcpy(tmp, norm, nlen + 1);
    size_t cuts[128];   /* 仅存祖先前缀长度，命中路径全程零分配 */
    int ns = 0;
    size_t cur = nlen;
    while (cur > 1) {
        char *q = strrchr(tmp, '/');
        if (!q || q == tmp) break;
        *q = '\0';
        cur = (size_t)(q - tmp);
        unsigned ci = dhash(tmp) & (DCACHE - 1);
        if (clean_dirs[ci] && strcmp(clean_dirs[ci], tmp) == 0)
            return 0; /* 该祖先干净 => 整支干净 */
        struct stat sb;
        if (real_stat(tmp, &sb) == 0 && ino_exact(sb.st_dev, sb.st_ino))
            return 1;
        if (ns < (int)(sizeof cuts / sizeof cuts[0])) cuts[ns++] = cur;
    }
    /* 到根都未命中：此时才需要分配，把访问过的祖先目录标记为干净 */
    for (int k = 0; k < ns; k++) {
        char *dup = strndup(norm, cuts[k]);
        if (dup) clean_put_owned(dup);
    }
    return 0;
}

/* 对已词法绝对化的路径做匹配：字符串 -> 一次 stat 的 inode 精确匹配 -> 祖先检查 */
static int abs_hidden(const char *norm)
{
    if (abs_str_match(norm, strlen(norm))) return 1;
    if (!has_ident) return 0;
    struct stat sb;
    if (real_stat(norm, &sb) != 0) return 0;
    if (redir_ident_match(sb.st_dev, sb.st_ino)) return 0; /* 重定向目标的别名路径，本次豁免 */
    if (ino_exact(sb.st_dev, sb.st_ino)) return 1;
    return ancestor_hidden(norm);
}

/* readdir/scandir 专用：所在目录已确认干净，无需回溯。
   先用 d_ino 过滤，避免绝大多数条目发生 stat。 */
static int entry_hidden(const char *full, ino_t d_ino)
{
    if (abs_str_match(full, strlen(full))) return 1;
    if (!has_ident) return 0;
    if (d_ino != 0) {
        int maybe = 0;
        for (int i = 0; i < nident; i++)
            if (ident_ino[i] == d_ino) { maybe = 1; break; }
        if (!maybe) return 0;
    }
    struct stat sb;
    if (real_stat(full, &sb) != 0) return 0;
    return ino_exact(sb.st_dev, sb.st_ino);
}

/* 含 ".." 且中间夹了符号链接时，词法折叠得不到正确祖先，退回 libc realpath
   （带重入保护）以保持与原实现一致的语义；普通路径不会走到这里。 */
static int realpath_canon(const char *path, char *out)
{
    return canon_path(path, out) != NULL;
}

/* path 是否在 ALLOW_ACCESS 放行名单中（词法绝对化；含 ".." 时走 realpath）。
   目录条目对整棵子树生效：命中精确路径，或以 '/' 为边界的子路径（与 HIDE_FILES 一致）。 */
static int access_allowed(const char *path)
{
    if (naitems == 0 || !path || !*path) return 0;
    const char *p = path;
    char canon[PATH_MAX];
    if (strstr(path, "..")) {
        if (!realpath_canon(path, canon)) return 0;
        p = canon;
    } else {
        if (!lex_abs(path, canon, sizeof canon)) return 0;
        p = canon;
    }
    size_t n = strlen(p);
    for (int i = 0; i < naitems; i++) {
        size_t l = aitem_len[i];
        if (l > n || memcmp(p, aitems[i], l) != 0) continue;
        if (l == n || p[l] == '/') return 1;
    }
    return 0;
}

/* 统一入口：零成本字符串匹配优先，只有确实需要时才做词法绝对化 */
static int path_hidden(const char *path)
{
    if (!path || !*path || npitems == 0) return 0;
    if (redir_target(path)) return 0; /* 重定向目标本次豁免 */
    if (strstr(path, "..")) {
        char canon[PATH_MAX];
        if (realpath_canon(path, canon)) return abs_hidden(canon);
    }
    char norm[PATH_MAX];
    if (!lex_abs(path, norm, sizeof norm)) return 0;
    return abs_hidden(norm);
}

/* stat 族复用：先做零系统调用的字符串匹配；未命中时输出词法绝对路径，
   供调用方在其真实 stat 成功后直接拿 st_dev/st_ino 做 inode 校验，省掉一次 stat。 */
static int path_hidden_pre(const char *path, char *norm, size_t bufsz, int *have_norm)
{
    *have_norm = 0;
    if (!path || !*path || npitems == 0) return 0;
    if (redir_target(path)) return 0; /* 重定向目标本次豁免 */
    if (strstr(path, "..")) return path_hidden(path); /* 罕见：退回完整匹配 */
    if (lex_abs(path, norm, bufsz)) {
        *have_norm = 1;
        return abs_str_match(norm, strlen(norm));
    }
    return 0;
}

/* dirfd 感知版本：相对路径按 dirfd 解析后再做隐藏/放行匹配（普通路径零额外开销）。 */
static int path_hidden_at(int dirfd, const char *path)
{
    if (!path || !*path || path[0] == '/' || dirfd == AT_FDCWD)
        return path_hidden(path);
    char abs[PATH_MAX];
    if (!resolve_at(dirfd, path, abs, sizeof abs)) return path_hidden(path);
    return path_hidden(abs);
}

static int access_allowed_at(int dirfd, const char *path)
{
    if (naitems == 0 || !path || !*path || path[0] == '/' || dirfd == AT_FDCWD)
        return access_allowed(path);
    char abs[PATH_MAX];
    if (!resolve_at(dirfd, path, abs, sizeof abs)) return access_allowed(path);
    return access_allowed(abs);
}

/* ---------- 符号解析 ---------- */

/* 解析下一个定义；失败不再 _exit（可选符号可能缺失），返回 NULL 由调用方降级。
   用锁串行化 dlsym，消除懒加载数据竞争。 */
static void *next(const char *sym)
{
    static pthread_mutex_t nxt_mtx = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&nxt_mtx);
    void *f = dlsym(RTLD_NEXT, sym);
    const char *err = f ? NULL : dlerror();
    pthread_mutex_unlock(&nxt_mtx);
    if (!f) dprintf(2, "hide.so: dlsym(%s) failed: %s\n", sym, err ? err : "?");
    return f;
}

/* 统一声明并懒加载 real 指针：real 的类型取自被钩函数本身的签名 */
#define GET_REAL(fn) \
    static __typeof__(fn) *real = NULL; \
    if (!real) real = next(#fn)

/* ---------- DIR* -> 目录路径 映射（让 readdir 能对绝对路径条目精确匹配） ---------- */

#define MAXDIRS 256
typedef struct { DIR *d; char *path; } dirmap_t;
static dirmap_t dirmap[MAXDIRS];
static int ndirmap;
static pthread_mutex_t dirmtx = PTHREAD_MUTEX_INITIALIZER;

/* 线程内缓存最近一次 DIR* -> 路径，重复 readdir 同一目录时完全免锁免查找 */
static __thread DIR *tls_dir;
static __thread char tls_dir_path[PATH_MAX];
static __thread int tls_dir_ok;

static void dir_record(DIR *d, const char *path)
{
    if (!d || !path || (!npitems && !nso)) return;
    char np[PATH_MAX];
    if (!lex_abs(path, np, sizeof np)) return;
    char *copy = strdup(np);
    if (!copy) return;
    pthread_mutex_lock(&dirmtx);
    if (ndirmap < MAXDIRS) {
        dirmap[ndirmap].d = d;
        dirmap[ndirmap].path = copy;
        ndirmap++;
    } else {
        /* 表满：淘汰最早一条（近似 FIFO），保证最近打开的目录仍可被跟踪 */
        free(dirmap[0].path);
        memmove(dirmap, dirmap + 1, (MAXDIRS - 1) * sizeof dirmap[0]);
        dirmap[MAXDIRS - 1].d = d;
        dirmap[MAXDIRS - 1].path = copy;
    }
    pthread_mutex_unlock(&dirmtx);
}

static void dir_forget(DIR *d)
{
    if (tls_dir_ok && tls_dir == d) tls_dir_ok = 0;
    pthread_mutex_lock(&dirmtx);
    for (int i = 0; i < ndirmap; i++) {
        if (dirmap[i].d == d) {
            free(dirmap[i].path);
            dirmap[i] = dirmap[ndirmap - 1];
            ndirmap--;
            break;
        }
    }
    pthread_mutex_unlock(&dirmtx);
}

static const char *dir_path(DIR *d)
{
    if (tls_dir_ok && tls_dir == d) return tls_dir_path;
    const char *found = NULL;
    pthread_mutex_lock(&dirmtx);
    for (int i = 0; i < ndirmap; i++) {
        if (dirmap[i].d == d) {
            size_t l = strlen(dirmap[i].path);
            if (l < sizeof tls_dir_path) {
                memcpy(tls_dir_path, dirmap[i].path, l + 1);
                tls_dir = d;
                tls_dir_ok = 1;
                found = tls_dir_path;
            }
            break;
        }
    }
    pthread_mutex_unlock(&dirmtx);
    return found;
}

/* ---------- /proc 路径识别 ---------- */

/* token 是否为 s 的“路径分量/前缀”命中：
   左边界为串首、'/' 或空白（maps 里路径前有空格）；右边界为串尾、'/' 或空白
   （后者也容忍映射路径的 " (deleted)" 后缀）。 */
static int path_token_match(const char *s, size_t slen, const char *tok, size_t tl)
{
    if (!tl || tl > slen) return 0;
    for (size_t i = 0; i + tl <= slen; i++) {
        if (s[i] != tok[0] || memcmp(s + i, tok, tl) != 0) continue;
        if (i != 0 && s[i - 1] != '/' && s[i - 1] != ' ' && s[i - 1] != '\t') continue;
        char nx = (i + tl < slen) ? s[i + tl] : '\0';
        if (nx == '\0' || nx == '/' || nx == ' ' || nx == '\t') return 1;
    }
    return 0;
}

/* 目录是否为 /proc/.../map_files */
static int is_map_files_dir(const char *dp)
{
    static const char suf[] = "/map_files";
    size_t l = strlen(dp), sl = sizeof(suf) - 1;
    return l >= sl && memcmp(dp + l - sl, suf, sl) == 0;
}

/* 拼出 dp + "/" + name 到 full，成功返回 1 */
static int join_path(char *full, size_t sz, const char *dp, const char *name)
{
    size_t dl = strlen(dp), nl = strlen(name);
    if (dl + nl + 2 > sz) return 0;
    memcpy(full, dp, dl);
    full[dl] = '/';
    memcpy(full + dl + 1, name, nl + 1);
    return 1;
}

/* 读取符号链接目标（裸 syscall，绕过本库钩子）。成功返回长度（>0）并 NUL 结尾。 */
static ssize_t readlink_raw(const char *path, char *buf, size_t sz)
{
    ssize_t n = syscall(__NR_readlinkat, AT_FDCWD, path, buf, sz - 1);
    if (n <= 0 || (size_t)n >= sz) return -1;
    buf[n] = '\0';
    return n;
}

/* 长度 slen 的字符串 s 是否命中任一 HIDE_SO token */
static int so_match(const char *s, size_t slen)
{
    for (int i = 0; i < nso; i++)
        if (path_token_match(s, slen, so_tokens[i], so_token_len[i])) return 1;
    return 0;
}

/* 读取 map_files 符号链接 full 的目标，判断是否命中 HIDE_SO */
static int so_target_hidden(const char *full)
{
    if (nso == 0) return 0;
    char tgt[PATH_MAX];
    ssize_t n = readlink_raw(full, tgt, sizeof tgt);
    return n > 0 && so_match(tgt, (size_t)n);
}

/* 廉价过滤：只有 /proc 下的绝对路径才可能是 map_files 条目。
   相对路径保持旧行为（继续 strstr 匹配）。 */
static int maybe_map_files(const char *path)
{
    if (nso == 0 || !path) return 0;
    if (path[0] == '/' && strncmp(path, "/proc/", 6) != 0) return 0;
    return strstr(path, "/map_files/") != NULL;
}

/* map_files 下的符号链接若指向被 HIDE_SO 命中的库则视为不存在 */
static int map_link_hidden(const char *path, const char *buf, ssize_t r)
{
    if (r <= 0 || !maybe_map_files(path)) return 0;
    size_t n = (size_t)r;
    if (n >= PATH_MAX) n = PATH_MAX - 1;
    return so_match(buf, n);
}

/* 路径位于 /proc/.../map_files/<addr> 且其符号链接目标命中 HIDE_SO。
    用于 open/stat/access 等按地址直接访问时也视为不存在。 */
static int map_files_entry_hidden(const char *path)
{
    if (!maybe_map_files(path)) return 0;
    char tgt[PATH_MAX];
    ssize_t n = readlink_raw(path, tgt, sizeof tgt);
    return n > 0 && so_match(tgt, (size_t)n);
}

/* ---------- 通用“不存在”判定与包装宏 ---------- */

/* 命中隐藏路径或命中 map_files 下的隐藏库符号链接 */
static int hidden_enoent(const char *path)
{
    return path_hidden(path) || map_files_entry_hidden(path);
}

/* dirfd 感知版本（供 *_at 钩子使用） */
static int hidden_enoent_at(int dirfd, const char *path)
{
    return path_hidden_at(dirfd, path) || map_files_entry_hidden(path);
}

#define HIDE_ENOENT(path)    do { if (hidden_enoent(path)) { errno = ENOENT; return -1; } } while (0)
#define HIDE_ENOENT_AT(d, p) do { if (hidden_enoent_at((d), (p))) { errno = ENOENT; return -1; } } while (0)
#define HIDE_ENULL(path)     do { if (hidden_enoent(path)) { errno = ENOENT; return NULL; } } while (0)
#define HIDE_EEXIST(path)    do { if (path_hidden(path)) { errno = EEXIST; return -1; } } while (0)
#define HIDE_EEXIST_AT(d, p) do { if (path_hidden_at((d), (p))) { errno = EEXIST; return -1; } } while (0)

#define GUARD_REAL_INT() do { if (!real) { errno = ENOSYS; return -1; } } while (0)

/* int fn(const char *path) */
#define W_INT_PATH(fn) \
    int fn(const char *path) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR(path)) HIDE_ENOENT(path); \
        return real(path); \
    }

/* int fn(const char *path, T1 a1) */
#define W_INT_PATH1(fn, T1, a1) \
    int fn(const char *path, T1 a1) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR(path)) HIDE_ENOENT(path); \
        return real(path, a1); \
    }

/* int fn(const char *path, T1 a1, T2 a2) */
#define W_INT_PATH2(fn, T1, a1, T2, a2) \
    int fn(const char *path, T1 a1, T2 a2) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR(path)) HIDE_ENOENT(path); \
        return real(path, a1, a2); \
    }

/* int fn(int dirfd, const char *path, T1 a1) */
#define W_INT_AT1(fn, T1, a1) \
    int fn(int dirfd, const char *path, T1 a1) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR_AT(dirfd, path)) HIDE_ENOENT_AT(dirfd, path); \
        return real(dirfd, path, a1); \
    }

/* int fn(int dirfd, const char *path, T1 a1, T2 a2) */
#define W_INT_AT2(fn, T1, a1, T2, a2) \
    int fn(int dirfd, const char *path, T1 a1, T2 a2) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR_AT(dirfd, path)) HIDE_ENOENT_AT(dirfd, path); \
        return real(dirfd, path, a1, a2); \
    }

/* int fn(const char *a, const char *b)（两路径都判隐藏；重定向到隐藏目标时豁免） */
#define W_TWO_PATH(fn) \
    int fn(const char *a, const char *b) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR(a) && path_hidden(a)) { errno = ENOENT; return -1; } \
        if (!REDIR(b) && path_hidden(b)) { errno = ENOENT; return -1; } \
        return real(a, b); \
    }

/* int fn(int odirfd, const char *a, int ndirfd, const char *b) */
#define W_TWO_AT3(fn) \
    int fn(int odirfd, const char *a, int ndirfd, const char *b) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR_AT(odirfd, a) && path_hidden_at(odirfd, a)) { errno = ENOENT; return -1; } \
        if (!REDIR_AT(ndirfd, b) && path_hidden_at(ndirfd, b)) { errno = ENOENT; return -1; } \
        return real(odirfd, a, ndirfd, b); \
    }

/* int fn(int odirfd, const char *a, int ndirfd, const char *b, Tf af) */
#define W_TWO_AT4(fn, Tf, af) \
    int fn(int odirfd, const char *a, int ndirfd, const char *b, Tf af) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR_AT(odirfd, a) && path_hidden_at(odirfd, a)) { errno = ENOENT; return -1; } \
        if (!REDIR_AT(ndirfd, b) && path_hidden_at(ndirfd, b)) { errno = ENOENT; return -1; } \
        return real(odirfd, a, ndirfd, b, af); \
    }

/* ---------- 目录列举 ---------- */

static int skip_dir_entry(const char *dp, const char *name, ino_t ino)
{
    if (!dp) return 0;
    char full[PATH_MAX];
    if (!join_path(full, sizeof full, dp, name)) return 0;
    if (npitems && entry_hidden(full, ino)) return 1;
    if (nso && is_map_files_dir(dp) && so_target_hidden(full)) return 1;
    return 0;
}

struct dirent *readdir(DIR *dirp)
{
    GET_REAL(readdir);
    if (!real) { errno = ENOSYS; return NULL; }
    if (!npitems && !nso) return real(dirp);
    const char *dp = dir_path(dirp);
    /* 只有存在路径条目、或当前目录可能是 map_files 时才需要逐项过滤 */
    if (npitems == 0 && !(nso && dp && is_map_files_dir(dp))) return real(dirp);
    struct dirent *d;
    while ((d = real(dirp)) != NULL)
        if (!skip_dir_entry(dp, d->d_name, d->d_ino)) return d;
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp)
{
    GET_REAL(readdir64);
    if (!real) { errno = ENOSYS; return NULL; }
    if (!npitems && !nso) return real(dirp);
    const char *dp = dir_path(dirp);
    if (npitems == 0 && !(nso && dp && is_map_files_dir(dp))) return real(dirp);
    struct dirent64 *d;
    while ((d = real(dirp)) != NULL)
        if (!skip_dir_entry(dp, d->d_name, d->d_ino)) return d;
    return NULL;
}

int scandir(const char *dir, struct dirent ***namelist,
            int (*filter)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **))
{
    static int (*real)(const char *, struct dirent ***,
                       int (*)(const struct dirent *),
                       int (*)(const struct dirent **, const struct dirent **)) = NULL;
    if (!real) real = next("scandir");
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_SCOPE();
    if (!REDIR(dir) && path_hidden(dir)) { errno = ENOENT; return -1; }
    int n = real(dir, namelist, filter, compar);
    if (n <= 0 || !namelist || !*namelist) return n;
    char dbuf[PATH_MAX];
    const char *dp = ((npitems || nso) && lex_abs(dir, dbuf, sizeof dbuf)) ? dbuf : NULL;
    if (npitems == 0 && !(nso && dp && is_map_files_dir(dp))) return n;
    int kept = 0;
    for (int i = 0; i < n; i++) {
        struct dirent *d = (*namelist)[i];
        if (!d) continue;
        if (skip_dir_entry(dp, d->d_name, d->d_ino)) free(d);
        else (*namelist)[kept++] = d;
    }
    if (kept != n) {
        struct dirent **nn = realloc(*namelist,
            (size_t)(kept ? kept : 1) * sizeof(struct dirent *));
        if (nn) *namelist = nn;
    }
    return kept;
}

/* ---------- /proc 文本脱敏 ----------
   进程读取 /proc/<pid>/{environ,maps,...,mounts,...} 时按配置过滤内容。
   environ 由内核在 read 时生成，无法逐块改写，故拦截 open：一次性读出真实内容、
   过滤后写入 memfd，返回该 fd，后续 read/lseek/fstat/mmap 均正常。 */

/* 解析 /proc/(self|thread-self|<pid>)(/task/<tid>)?/ 之后的部分；不是则返回 NULL */
static const char *proc_tail(const char *p)
{
    if (!p || strncmp(p, "/proc/", 6) != 0) return NULL;
    const char *q = p + 6;
    if (strncmp(q, "self/", 5) == 0) {
        q += 5;
    } else if (strncmp(q, "thread-self/", 12) == 0) {
        q += 12;
    } else if (*q >= '0' && *q <= '9') {
        while (*q >= '0' && *q <= '9') q++;
        if (*q != '/') return NULL;
        q++;
    }
    /* 否则为 /proc/<name> 直接形式（如 /proc/mounts），q 原样返回 */
    if (strncmp(q, "task/", 5) == 0) {
        q += 5;
        if (*q < '0' || *q > '9') return NULL;
        while (*q >= '0' && *q <= '9') q++;
        if (*q != '/') return NULL;
        q++;
    }
    return q;
}

enum { PK_NONE = 0, PK_ENVIRON, PK_SO, PK_MOUNT };

static int proc_kind(const char *path)
{
    const char *t = proc_tail(path);
    if (!t) return PK_NONE;
    if (strcmp(t, "environ") == 0) return PK_ENVIRON;
    if (strcmp(t, "maps") == 0 || strcmp(t, "smaps") == 0 ||
        strcmp(t, "smaps_rollup") == 0) return PK_SO;
    if (strcmp(t, "mounts") == 0 || strcmp(t, "mountinfo") == 0 ||
        strcmp(t, "mountstats") == 0 || strcmp(t, "mountstat") == 0) return PK_MOUNT;
    return PK_NONE; /* map_files/mem/pagemap 另行处理或不处理 */
}

/* 取 [s,end) 中第 idx 个（0 基）空白分隔字段；失败返回 NULL */
static const char *nth_field(const char *s, const char *end, int idx, size_t *flen)
{
    const char *p = s;
    for (int k = 0; k <= idx; k++) {
        while (p < end && (*p == ' ' || *p == '\t')) p++;
        if (p >= end) return NULL;
        const char *q = p;
        while (q < end && *q != ' ' && *q != '\t') q++;
        if (k == idx) { *flen = (size_t)(q - p); return p; }
        p = q;
    }
    return NULL;
}

static int so_line_drop(const char *line, size_t len)
{
    return so_match(line, len);
}

/* mountinfo 的挂载点是第 5 字段；mounts/mountstats 是第 2 字段 */
static int mount_field_index(const char *path)
{
    const char *t = proc_tail(path);
    if (t && strcmp(t, "mountinfo") == 0) return 4;
    return 1;
}

static int mount_line_drop(const char *line, size_t len, int idx)
{
    if (nmnt == 0) return 0;
    size_t flen = 0;
    const char *f = nth_field(line, line + len, idx, &flen);
    if (!f) return 0;
    for (int i = 0; i < nmnt; i++) {
        size_t tl = mnt_token_len[i];
        if (flen == tl && memcmp(f, mnt_tokens[i], tl) == 0) return 1;
        if (flen > tl && memcmp(f, mnt_tokens[i], tl) == 0 && f[tl] == '/') return 1;
    }
    return 0;
}

/* 路径本身是否为被 HIDE_MOUNT 隐藏的挂载点（精确或前缀） */
static int mount_path_hidden(const char *path)
{
    if (nmnt == 0 || !path || !*path) return 0;
    char norm[PATH_MAX];
    if (!lex_abs(path, norm, sizeof norm)) return 0;
    size_t pl = strlen(norm);
    for (int i = 0; i < nmnt; i++) {
        size_t tl = mnt_token_len[i];
        if (pl == tl && memcmp(norm, mnt_tokens[i], tl) == 0) return 1;
        if (pl > tl && memcmp(norm, mnt_tokens[i], tl) == 0 && norm[tl] == '/') return 1;
    }
    return 0;
}

/* 单条是否应删除（environ 按配置变量表匹配，LD_PRELOAD 仅精确匹配目标值） */
static int seg_drop(const char *s, size_t n, int kind, int midx)
{
    if (kind == PK_ENVIRON) {
        const size_t lp = g_ld_entry ? (11 + g_ld_vlen) : 0;
        if (lp && n == lp && memcmp(s, g_ld_entry, lp) == 0) return 1;
        for (int k = 0; k < CFG_N; k++) {
            if (k == CFG_LD) continue; /* 仅按精确值删除，见上 */
            size_t l = cfg_vars[k].len;
            if (n > l && s[l] == '=' && memcmp(s, cfg_vars[k].name, l) == 0) return 1;
        }
        return 0;
    }
    if (kind == PK_SO) return so_line_drop(s, n);
    return mount_line_drop(s, n, midx);
}

/* memfd 写出缓冲：把海量小行合并为较大的 write，显著减少系统调用 */
typedef struct {
    int fd;
    int err;
    size_t len;
    char buf[65536];
} obuf;

static void obuf_flush(obuf *o)
{
    if (!o->err && o->len && write_all(o->fd, o->buf, o->len) < 0) o->err = 1;
    o->len = 0;
}

static void obuf_write(obuf *o, const void *p, size_t n)
{
    if (o->err) return;
    if (n >= sizeof o->buf) { /* 超大块直写，避免无谓拷贝 */
        obuf_flush(o);
        if (write_all(o->fd, p, n) < 0) o->err = 1;
        return;
    }
    if (o->len + n > sizeof o->buf) obuf_flush(o);
    memcpy(o->buf + o->len, p, n);
    o->len += n;
}

#define PROC_MAX_SEG (8u << 20) /* 单条上限：/proc 文本远小于此，超限即失败关闭 */

/* 流式过滤 /proc 文本：边读边写 memfd，只保留一个不完整尾段，避免整文件双缓冲。
   返回 1 表示已处理（*out 为结果 fd，失败为 -1）；返回 0 表示不处理该路径。 */
static int handle_proc_file(const char *path, int flags, int *out)
{
    int kind = proc_kind(path);
    if (kind == PK_NONE) return 0;
    if (kind == PK_SO && nso == 0) return 0;
    if (kind == PK_MOUNT && nmnt == 0) return 0;
    if (flags & O_PATH) return 0; /* O_PATH 需保持原 fd 语义，不替换成 memfd */
    if ((flags & O_ACCMODE) != O_RDONLY) return 0;

    int rfd = raw_open_ro(path);
    if (rfd < 0) { *out = -1; return 1; }
    int mfd = raw_memfd("proc", (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0);
    if (mfd < 0) { /* 失败关闭，绝不返回原始内容 */
        close(rfd);
        errno = EIO;
        *out = -1;
        return 1;
    }

    obuf ob = { .fd = mfd };
    char chunk[65536];
    char *carry = NULL;
    size_t clen = 0, ccap = 0;
    const char sep = (kind == PK_ENVIRON) ? '\0' : '\n';
    const int midx = (kind == PK_MOUNT) ? mount_field_index(path) : 0;
    int ok = 1, fail_errno = EIO;

    for (;;) {
        ssize_t r = raw_read(rfd, chunk, sizeof chunk);
        if (r < 0) { ok = 0; break; }
        if (r == 0) break;
        /* 单条超过上限（异常输入）：失败关闭，绝不把未过滤内容写出去 */
        if ((size_t)r > PROC_MAX_SEG - clen) { ok = 0; fail_errno = EFBIG; break; }
        if (clen + (size_t)r > ccap) {
            size_t nc = ccap ? ccap : 8192;
            while (nc < clen + (size_t)r) nc *= 2;
            char *nb = realloc(carry, nc);
            if (!nb) { ok = 0; fail_errno = ENOMEM; break; }
            carry = nb; ccap = nc;
        }
        memcpy(carry + clen, chunk, (size_t)r);
        clen += (size_t)r;

        size_t start = 0;
        for (size_t i = 0; i < clen; i++) {
            if (carry[i] != sep) continue;
            size_t llen = i - start;
            if (!seg_drop(carry + start, llen, kind, midx)) {
                obuf_write(&ob, carry + start, llen);
                obuf_write(&ob, &sep, 1);
            }
            start = i + 1;
        }
        if (start) { memmove(carry, carry + start, clen - start); clen -= start; }
    }
    if (ok && clen && !seg_drop(carry, clen, kind, midx)) {
        obuf_write(&ob, carry, clen);
        if (sep == '\0') obuf_write(&ob, &sep, 1);
    }
    if (ok && !ob.err) obuf_flush(&ob);
    if (ob.err) ok = 0;
    free(carry);
    close(rfd);
    if (!ok) {
        close(mfd);
        errno = fail_errno;
        *out = -1;
        return 1;
    }
    raw_seek(mfd, 0);
    *out = mfd;
    return 1;
}

/* dirfd 感知版本：相对路径先解析为绝对路径再识别 /proc（handle_proc_file 内部
   用裸 open 读取，必须拿到绝对路径才能命中 dirfd 指向的 /proc）。 */
static int handle_proc_file_at(int dirfd, const char *path, int flags, int *out)
{
    if (path && path[0] == '/') return handle_proc_file(path, flags, out);
    char abs[PATH_MAX];
    if (!resolve_at(dirfd, path, abs, sizeof abs)) return 0;
    if (proc_kind(abs) == PK_NONE) return 0;
    return handle_proc_file(abs, flags, out);
}

/* ---------- 属性检查 ---------- */

/* stat 前判定 + 输出词法绝对路径供事后 inode 校验 */
static int stat_hidden_pre(const char *path, char *norm, int *have_norm)
{
    if (path_hidden_pre(path, norm, PATH_MAX, have_norm)) return 1;
    return map_files_entry_hidden(path);
}

/* int fn(const char *path, T buf)：stat/lstat 族，真实 stat 后再做 inode 身份校验 */
#define W_STAT_IMPL(fn, T) \
    int fn(const char *path, T buf) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        int redir = REDIR(path); \
        int skip = redir || redir_target(path); \
        char norm[PATH_MAX]; \
        int have_norm = 0; \
        if (!skip && stat_hidden_pre(path, norm, &have_norm)) { errno = ENOENT; return -1; } \
        int r = real(path, buf); \
        if (!skip && r == 0 && has_ident && \
            !redir_ident_match(buf->st_dev, buf->st_ino) && \
            (ino_exact(buf->st_dev, buf->st_ino) || \
             (has_dir_ident && have_norm && ancestor_hidden(norm)))) { \
            errno = ENOENT; \
            return -1; \
        } \
        return r; \
    }

W_STAT_IMPL(stat, struct stat *)
W_STAT_IMPL(stat64, struct stat64 *)
W_STAT_IMPL(lstat, struct stat *)
W_STAT_IMPL(lstat64, struct stat64 *)

/* bionic 无 newfstatat 符号，newfstatat 语义即 fstatat/fstatat64。
   ALLOW_ACCESS 只作用于这两个探测钩子：命中重定向时跳过隐藏（目标即便在 HIDE_FILES
   也可达）；否则对字面路径判定，命中名单才豁免 HIDE_FILES。
   其余钩子（stat/lstat/statx/access/open/...）不受 ALLOW 影响。 */
int fstatat(int dirfd, const char *path, struct stat *buf, int flags)
{
    GET_REAL(fstatat);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    int redir = REDIR_AT(dirfd, path);         /* 受 REDIRECT_FILES 影响 */
    if (!redir && !access_allowed_at(dirfd, path))
        HIDE_ENOENT_AT(dirfd, path);
    return real(dirfd, path, buf, flags);
}

int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags)
{
    GET_REAL(fstatat64);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_SCOPE();
    int redir = REDIR_AT(dirfd, path);
    if (!redir && !access_allowed_at(dirfd, path))
        HIDE_ENOENT_AT(dirfd, path);
    return real(dirfd, path, buf, flags);
}

int statx(int dirfd, const char *path, int flags, unsigned int mask, struct statx *buf)
{
    GET_REAL(statx);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_SCOPE();
    if (!REDIR_AT(dirfd, path))
        HIDE_ENOENT_AT(dirfd, path);
    return real(dirfd, path, flags, mask, buf);
}

W_INT_PATH1(access, int, mode)

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    GET_REAL(faccessat);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    int redir = REDIR_AT(dirfd, path);         /* 受 REDIRECT_FILES 影响 */
    if (!redir && !access_allowed_at(dirfd, path))
        HIDE_ENOENT_AT(dirfd, path);
    return real(dirfd, path, mode, flags);
}

char *realpath(const char *path, char *resolved)
{
    GET_REAL(realpath);
    if (!real) { errno = ENOSYS; return NULL; }
    REDIR_SCOPE();
    if (!REDIR(path) && hidden_enoent(path)) { errno = ENOENT; return NULL; }
    return real(path, resolved);
}

/* ---------- readlink ---------- */

ssize_t readlink(const char *path, char *buf, size_t size)
{
    GET_REAL(readlink);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_SCOPE();
    int redir = REDIR(path);
    if (!redir && hidden_enoent(path)) { errno = ENOENT; return -1; }
    ssize_t r = real(path, buf, size);
    if (!redir && map_link_hidden(path, buf, r)) { errno = ENOENT; return -1; }
    return r;
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t size)
{
    GET_REAL(readlinkat);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_SCOPE();
    int redir = REDIR_AT(dirfd, path);
    if (!redir && hidden_enoent_at(dirfd, path)) { errno = ENOENT; return -1; }
    ssize_t r = real(dirfd, path, buf, size);
    if (!redir && map_link_hidden(path, buf, r)) { errno = ENOENT; return -1; }
    return r;
}

ssize_t __readlinkat_chk(int dirfd, const char *path, char *buf, size_t bufsiz, size_t buflen)
{
    GET_REAL(__readlinkat_chk);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_SCOPE();
    int redir = REDIR_AT(dirfd, path);
    if (!redir && hidden_enoent_at(dirfd, path)) { errno = ENOENT; return -1; }
    ssize_t r = real(dirfd, path, buf, bufsiz, buflen);
    if (!redir && map_link_hidden(path, buf, r)) { errno = ENOENT; return -1; }
    return r;
}

/* ---------- 扩展属性（含 SELinux 标签 security.selinux） ----------
   仅受 REDIRECT_FILES 控制：命中重定向时读写目标改为 dst 并跳过隐藏判定（目标可达）；
   未重定向时被隐藏路径视为不存在；
   不参与 ALLOW_ACCESS（ALLOW 只作用于 fstatat/fstatat64/faccessat 与 execve）。
   GNU stat -c %C / getfattr / lgetfilecon 等最终都落到 lgetxattr/getxattr。 */

#define W_XATTR_GET(fn) \
    ssize_t fn(const char *path, const char *name, void *value, size_t size) \
    { \
        GET_REAL(fn); \
        if (!real) { errno = ENOSYS; return -1; } \
        REDIR_SCOPE(); \
        if (!REDIR(path)) HIDE_ENOENT(path); \
        return real(path, name, value, size); \
    }

W_XATTR_GET(getxattr)
W_XATTR_GET(lgetxattr)

#define W_XATTR_LIST(fn) \
    ssize_t fn(const char *path, char *list, size_t size) \
    { \
        GET_REAL(fn); \
        if (!real) { errno = ENOSYS; return -1; } \
        REDIR_SCOPE(); \
        if (!REDIR(path)) HIDE_ENOENT(path); \
        return real(path, list, size); \
    }

W_XATTR_LIST(listxattr)
W_XATTR_LIST(llistxattr)

#define W_XATTR_SET(fn) \
    int fn(const char *path, const char *name, const void *value, size_t size, int flags) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR(path)) HIDE_ENOENT(path); \
        return real(path, name, value, size, flags); \
    }

W_XATTR_SET(setxattr)
W_XATTR_SET(lsetxattr)

#define W_XATTR_REMOVE(fn) \
    int fn(const char *path, const char *name) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR(path)) HIDE_ENOENT(path); \
        return real(path, name); \
    }

W_XATTR_REMOVE(removexattr)
W_XATTR_REMOVE(lremovexattr)

/* ---------- 文件系统信息：被隐藏的挂载点也视为不存在 ---------- */

#define W_STATVFS(fn, T) \
    int fn(const char *path, T buf) \
    { \
        GET_REAL(fn); \
        if (!real) { errno = ENOSYS; return -1; } \
        REDIR_SCOPE(); \
        if (!REDIR(path) && (hidden_enoent(path) || mount_path_hidden(path))) { errno = ENOENT; return -1; } \
        return real(path, buf); \
    }

W_STATVFS(statfs, struct statfs *)
W_STATVFS(statfs64, struct statfs64 *)
W_STATVFS(statvfs, struct statvfs *)
W_STATVFS(statvfs64, struct statvfs64 *)

/* ---------- 卸载：被 HIDE_MOUNT 隐藏的挂载点视为“不存在” ----------
   直接 syscall(SYS_umount2,...) 绕过本库的调用无法拦截。 */

int umount(const char *target)
{
    GET_REAL(umount);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (mount_path_hidden(target)) { errno = EINVAL; return -1; }
    return real(target);
}

int umount2(const char *target, int flags)
{
    GET_REAL(umount2);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (mount_path_hidden(target)) { errno = EINVAL; return -1; }
    return real(target, flags);
}

/* ---------- 打开/读取 ---------- */

/* int fn(const char *path, int flags, ...)。open 家族不参与 ALLOW_ACCESS：
   一律重定向、判隐藏、做 /proc 过滤（放行只走 fstatat/faccessat/execve）。 */
#define W_OPEN_IMPL(fn, realcall) \
    int fn(const char *path, int flags, ...) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR(path)) HIDE_ENOENT(path); \
        int fd; \
        if (handle_proc_file_at(AT_FDCWD, path, flags, &fd)) return fd; \
        va_list ap; \
        va_start(ap, flags); \
        int mode = ((flags & (O_CREAT | O_TMPFILE)) ? va_arg(ap, int) : 0); \
        va_end(ap); \
        return realcall; \
    }

/* int fn(int dirfd, const char *path, int flags, ...)；open 家族不参与 ALLOW_ACCESS */
#define W_OPENAT_IMPL(fn, realcall) \
    int fn(int dirfd, const char *path, int flags, ...) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_INT(); \
        REDIR_SCOPE(); \
        if (!REDIR_AT(dirfd, path)) HIDE_ENOENT_AT(dirfd, path); \
        int fd; \
        if (handle_proc_file_at(dirfd, path, flags, &fd)) return fd; \
        va_list ap; \
        va_start(ap, flags); \
        int mode = ((flags & (O_CREAT | O_TMPFILE)) ? va_arg(ap, int) : 0); \
        va_end(ap); \
        return realcall; \
    }

W_OPEN_IMPL(open, real(path, flags, mode))
W_OPEN_IMPL(open64, real(path, flags, mode))
W_OPENAT_IMPL(openat, real(dirfd, path, flags, mode))
W_OPENAT_IMPL(openat64, real(dirfd, path, flags, mode))

int __open_2(const char *path, int flags)
{
    GET_REAL(__open_2);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_SCOPE();
    if (!REDIR(path)) HIDE_ENOENT(path);
    int fd;
    if (handle_proc_file_at(AT_FDCWD, path, flags, &fd)) return fd;
    return real(path, flags);
}

int __openat_2(int dirfd, const char *path, int flags)
{
    GET_REAL(__openat_2);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_SCOPE();
    if (!REDIR_AT(dirfd, path)) HIDE_ENOENT_AT(dirfd, path);
    int fd;
    if (handle_proc_file_at(dirfd, path, flags, &fd)) return fd;
    return real(dirfd, path, flags);
}

W_INT_PATH1(creat, mode_t, mode)
W_INT_PATH1(creat64, mode_t, mode)

#define GUARD_REAL_NULL() do { if (!real) { errno = ENOSYS; return NULL; } } while (0)

#define W_FOPEN(fn) \
    FILE *fn(const char *path, const char *mode) \
    { \
        GET_REAL(fn); \
        GUARD_REAL_NULL(); \
        REDIR_SCOPE(); \
        if (!REDIR(path)) HIDE_ENULL(path); \
        return real(path, mode); \
    }

W_FOPEN(fopen)
W_FOPEN(fopen64)

FILE *freopen(const char *path, const char *mode, FILE *stream)
{
    GET_REAL(freopen);
    GUARD_REAL_NULL();
    REDIR_SCOPE();
    if (!REDIR(path)) HIDE_ENULL(path);
    return real(path, mode, stream);
}

FILE *freopen64(const char *path, const char *mode, FILE *stream)
{
    GET_REAL(freopen64);
    GUARD_REAL_NULL();
    REDIR_SCOPE();
    if (!REDIR(path)) HIDE_ENULL(path);
    return real(path, mode, stream);
}

DIR *opendir(const char *path)
{
    GET_REAL(opendir);
    GUARD_REAL_NULL();
    REDIR_SCOPE();
    if (!REDIR(path)) HIDE_ENULL(path);
    DIR *d = real(path);
    if (d) dir_record(d, path);
    return d;
}

DIR *fdopendir(int fd)
{
    GET_REAL(fdopendir);
    GUARD_REAL_NULL();
    REDIR_SCOPE();
    char link[64], target[PATH_MAX];
    int ln = snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    if (ln <= 0 || ln >= (int)sizeof link) return real(fd);
    ssize_t n = readlink_raw(link, target, sizeof target);
    if (n <= 0) return real(fd);
    if (path_hidden(target)) { errno = ENOENT; return NULL; }
    DIR *d = real(fd);
    if (d) dir_record(d, target);
    return d;
}

int closedir(DIR *dirp)
{
    GET_REAL(closedir);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (dirp) dir_forget(dirp);
    return real(dirp);
}

/* ---------- 保护：改名/删除/改属性一律 ENOENT ---------- */

W_INT_PATH(unlink)
W_INT_AT1(unlinkat, int, flags)
W_INT_PATH(remove)
W_INT_PATH(rmdir)
W_TWO_PATH(rename)
W_TWO_AT3(renameat)
W_TWO_AT4(renameat2, unsigned int, flags)

W_INT_PATH1(chmod, mode_t, mode)
W_INT_AT2(fchmodat, mode_t, mode, int, flags)
W_INT_PATH2(chown, uid_t, owner, gid_t, group)
W_INT_PATH2(lchown, uid_t, owner, gid_t, group)

int utimensat(int dirfd, const char *path, const struct timespec times[2], int flags)
{
    GET_REAL(utimensat);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (!REDIR_AT(dirfd, path)) HIDE_ENOENT_AT(dirfd, path);
    return real(dirfd, path, times, flags);
}

int utimes(const char *path, const struct timeval times[2])
{
    GET_REAL(utimes);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (!REDIR(path)) HIDE_ENOENT(path);
    return real(path, times);
}

W_INT_PATH1(utime, const struct utimbuf *, times)
W_INT_PATH1(truncate, off_t, length)
W_INT_PATH1(truncate64, off64_t, length)

W_TWO_PATH(link)
W_TWO_AT4(linkat, int, flags)

int symlink(const char *target, const char *linkpath)
{
    GET_REAL(symlink);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (!REDIR(linkpath)) HIDE_EEXIST(linkpath);
    return real(target, linkpath);
}

int symlinkat(const char *target, int dirfd, const char *linkpath)
{
    GET_REAL(symlinkat);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (!REDIR_AT(dirfd, linkpath)) HIDE_EEXIST_AT(dirfd, linkpath);
    return real(target, dirfd, linkpath);
}

int mkdir(const char *path, mode_t mode)
{
    GET_REAL(mkdir);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (!REDIR(path)) HIDE_EEXIST(path);
    return real(path, mode);
}

int mkdirat(int dirfd, const char *path, mode_t mode)
{
    GET_REAL(mkdirat);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (!REDIR_AT(dirfd, path)) HIDE_EEXIST_AT(dirfd, path);
    return real(dirfd, path, mode);
}

/* ---------- execve ----------
   静态链接程序执行前卸除 LD_PRELOAD 与 HIDE_FILES：hide.so 依赖动态链接器注入；
   静态链接（含静态 PIE）的 ELF 没有 PT_INTERP，动态链接器不会介入，LD_PRELOAD
   对其无效。若继续传给被 exec 的程序会污染其子进程环境，也会把隐藏名单
   （HIDE_FILES）泄露出去。故读 ELF 程序头判断是否含 PT_INTERP：没有则剥掉 envp
   里的配置再 exec。bionic 的 execvp/execvpe/fexecve 最终都经 PLT 调用 execve，
   故只需钩 execve。execve 同样参与路径重定向（先按 REDIRECT_FILES 改写 path）。 */

static uint16_t rl16(const unsigned char *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rl32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rl64(const unsigned char *p)
{
    return (uint64_t)rl32(p) | ((uint64_t)rl32(p + 4) << 32);
}

/* 返回 1 表示静态链接（无 PT_INTERP）。脚本则看其 shebang 解释器。 */
static int elf_is_static_depth(const char *path, int depth)
{
    if (!path || !*path || depth > 8) return 0;
    int fd = raw_open_ro(path);
    if (fd < 0) return 0;

    unsigned char hdr[64];
    ssize_t got = raw_read(fd, hdr, sizeof hdr);
    if (got < 16) { close(fd); return 0; }

    /* 脚本：解析 "#!interpreter" 并判断解释器 */
    if (hdr[0] == '#' && hdr[1] == '!') {
        raw_seek(fd, 2);
        unsigned char line[256];
        ssize_t n = raw_read(fd, line, sizeof(line) - 1);
        close(fd);
        if (n <= 0) return 0;
        line[n] = '\0';
        char *p = (char *)line;
        while (*p == ' ' || *p == '\t') p++;
        char *e = p;
        while (*e && *e != ' ' && *e != '\t' && *e != '\n' && *e != '\r') e++;
        *e = '\0';
        if (!*p) return 0;
        return elf_is_static_depth(p, depth + 1);
    }

    if (!(hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F')) {
        close(fd);
        return 0; /* 非 ELF，交给内核报 ENOEXEC */
    }
    if (hdr[5] != 1) { close(fd); return 0; } /* 仅处理小端 ELF */

    uint64_t phoff;
    uint16_t phentsize, phnum;
    if (hdr[4] == 2) { /* ELF64：头部 64 字节已随首次读取全部拿到 */
        if (got < 64) { close(fd); return 0; }
        phoff = rl64(hdr + 32);
        phentsize = rl16(hdr + 54);
        phnum = rl16(hdr + 56);
    } else if (hdr[4] == 1) { /* ELF32：头部 52 字节 */
        if (got < 52) { close(fd); return 0; }
        phoff = rl32(hdr + 28);
        phentsize = rl16(hdr + 42);
        phnum = rl16(hdr + 44);
    } else {
        close(fd);
        return 0;
    }

    /* 无程序头表：视作静态 */
    if (phoff == 0 || phentsize < 4 || phnum == 0) { close(fd); return 1; }

    int has_interp = 0;
    unsigned char ph[64];
    for (uint16_t i = 0; i < phnum; i++) {
        if (raw_seek(fd, (off_t)(phoff + (uint64_t)i * phentsize)) < 0) break;
        size_t want = phentsize < sizeof(ph) ? phentsize : sizeof(ph);
        if (raw_read(fd, ph, want) != (ssize_t)want) break;
        if (rl32(ph) == PT_INTERP) { has_interp = 1; break; }
    }
    close(fd);
    return !has_interp;
}

static int env_is(const char *e, const char *name, size_t n)
{
    return strncmp(e, name, n) == 0 && e[n] == '=';
}

/* 一次遍历 envp：判断是否含任一配置变量，并输出 LD_PRELOAD 的值。 */
static int envp_scan_cfg(char *const envp[], const char **ld_out)
{
    if (ld_out) *ld_out = NULL;
    if (!envp) return 0;
    int has = 0;
    for (int i = 0; envp[i]; i++) {
        const char *e = envp[i];
        for (int k = 0; k < CFG_N; k++) {
            size_t l = cfg_vars[k].len;
            if (strncmp(e, cfg_vars[k].name, l) != 0 || e[l] != '=') continue;
            has = 1;
            if (k == CFG_LD && ld_out) *ld_out = e + l + 1;
            break;
        }
    }
    return has;
}

typedef struct {
    const char *name;
    size_t nlen;
    int strip;
    const char *add;
} envop;

/* 按需重写 envp：strip 指定的条目剥掉，add 指定的条目追加。
    无需改动时原样返回 envp；改动时返回新数组（调用方负责 free）；
    OOM 时返回 NULL，调用方必须失败关闭，绝不能把未脱敏的配置泄露出去。 */
static char *const *build_env(char *const envp[], const envop *ops, int nops)
{
    int has = 0, any_add = 0;
    for (int k = 0; k < nops; k++) if (ops[k].add) any_add = 1;
    if (envp) {
        for (int i = 0; envp[i] && !has; i++)
            for (int k = 0; k < nops; k++)
                if (env_is(envp[i], ops[k].name, ops[k].nlen)) { has = 1; break; }
    }
    if (!has && !any_add) return envp;
    int n = 0;
    if (envp) while (envp[n]) n++;
    char **nv = malloc(((size_t)n + (size_t)nops + 1) * sizeof(char *));
    if (!nv) return NULL;
    int j = 0;
    for (int i = 0; i < n; i++) {
        int drop = 0;
        for (int k = 0; k < nops; k++)
            if (ops[k].strip && env_is(envp[i], ops[k].name, ops[k].nlen)) { drop = 1; break; }
        if (!drop) nv[j++] = envp[i];
    }
    for (int k = 0; k < nops; k++) if (ops[k].add) nv[j++] = (char *)ops[k].add;
    nv[j] = NULL;
    return (char *const *)nv;
}

/* SKIP_RESTRICTED_PATHS 前缀匹配。命中目标（如 /vendor、/odm、/product 等受限
   linker namespace）不允许从 /data 注入，否则报 "library ... is not accessible
   for the namespace" 并致命退出；执行前按静态目标做剥离清理。
   前缀列表由运行时 SKIP_RESTRICTED_PATHS 提供（冒号分隔）；未配置则不跳过。 */
static int path_is_skip_prefix(const char *p)
{
    for (int i = 0; i < nskip_pref; i++) {
        size_t l = strlen(skip_pref[i]);
        if (strncmp(p, skip_pref[i], l) == 0 && (p[l] == '\0' || p[l] == '/')) return 1;
    }
    return 0;
}

static int target_skip_inject(const char *path)
{
    if (!path || !*path || nskip_pref == 0) return 0;
    char buf[PATH_MAX];
    const char *p = path;
    if (path[0] != '/') {
        if (!lex_abs(path, buf, sizeof buf)) return 0;
        p = buf;
    }
    return path_is_skip_prefix(p);
}

/* envp 重写模式：全剥离 / 保留用户自设 LD_PRELOAD 只剥其余 / 剥离后按需回注 */
enum { ENV_STRIP_ALL = 0, ENV_KEEP_LD, ENV_REINJECT };

/* 按模式构造 ops 表（顺序与 cfg_vars 一致），再调用 build_env */
static char *const *env_rebuild(char *const envp[], int mode)
{
    envop ops[CFG_N];
    for (int k = 0; k < CFG_N; k++) {
        ops[k].name  = cfg_vars[k].name;
        ops[k].nlen  = cfg_vars[k].len;
        ops[k].strip = (mode == ENV_KEEP_LD) ? (k != CFG_LD) : 1;
        ops[k].add   = (mode == ENV_REINJECT) ? inject_entries[k] : NULL;
    }
    return build_env(envp, ops, CFG_N);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    GET_REAL(execve);
    GUARD_REAL_INT();
    REDIR_SCOPE();

    /* 放行名单优先：字面路径在 ALLOW_ACCESS 中时不参与重定向，直接执行原文件。
       否则按 REDIRECT_FILES 改写后再判隐藏；命中重定向则跳过隐藏（目标即便在
       HIDE_FILES 里也放行，仅本次操作；直接访问目标仍隐藏）。 */
    if (!access_allowed(path)) {
        int redir = REDIR(path);
        /* redir==0 时 path 未变，外层已判定 !access_allowed(path)，此处无需重复判定 */
        if (!redir && path_hidden(path)) { errno = ENOENT; return -1; }
    }

    const char *env_ld = NULL;
    int has = envp_scan_cfg(envp, &env_ld);
    int need_inject = 0;
    for (int k = 0; k < CFG_N; k++) if (inject_entries[k]) need_inject = 1;
    if (!has && !need_inject) return real(path, argv, envp);

    /* 选择重写模式：
       - SKIP_RESTRICTED_PATHS 命中目标：全剥离，避免从 /data 注入；
       - 用户自设过 LD_PRELOAD（或 envp 中的值不等于目标）：保留之，其余剥掉；
       - 静态目标，或本进程并非经 LD_PRELOAD 加载：只剥离不回注，避免配置泄露；
       - 动态目标且能保证子进程加载 hide.so：剥离后按需回注，保证配置一致。 */
    int mode;
    if (target_skip_inject(path)) {
        mode = ENV_STRIP_ALL;
    } else if (ld_preload_user_set ||
               (env_ld && (!g_ld_value || strcmp(env_ld, g_ld_value) != 0))) {
        mode = ENV_KEEP_LD;
    } else if (elf_is_static_depth(path, 0) || !inject_entries[CFG_LD]) {
        mode = ENV_STRIP_ALL;
    } else {
        mode = ENV_REINJECT;
    }

    char *const *nenv = env_rebuild(envp, mode);
    /* envp 为 NULL 时 NULL 是“无需改动”的合法结果；仅当原本有 envp 才视为 OOM */
    if (!nenv && envp) { errno = ENOMEM; return -1; } /* 失败关闭，绝不泄露配置 */
    int r = real(path, argv, nenv);
    if (nenv != envp) free((void *)nenv);
    return r;
}

/* ---------- getenv 脱敏 ----------
   getenv("HIDE_FILES") 恒为 NULL；getenv("LD_PRELOAD") 的值等于目标时返回 NULL，
   否则原样返回。注意 init_hidden 已绕过本钩子直接取 libc getenv 读配置。 */

static char *hide_env_getenv(char *(*real)(const char *), const char *name)
{
    size_t n = strlen(name);
    /* 先比长度，绝大多数非目标变量一次比较即排除 */
    for (int k = 0; k < CFG_N; k++) {
        if (cfg_vars[k].len != n || memcmp(name, cfg_vars[k].name, n) != 0) continue;
        if (k == CFG_LD) {
            char *v = real(name);
            if (v && g_ld_value && strcmp(v, g_ld_value) == 0) return NULL;
            return v;
        }
        return NULL;
    }
    return real(name);
}

char *getenv(const char *name)
{
    GET_REAL(getenv);
    if (!real) return NULL;
    return name ? hide_env_getenv(real, name) : real(name);
}

/* secure_getenv：本机 bionic 无此符号；存在时按同样规则脱敏，缺失时退回本库 getenv */
char *secure_getenv(const char *name)
{
    GET_REAL(secure_getenv);
    if (!real) return getenv(name);
    return name ? hide_env_getenv(real, name) : real(name);
}

/* ---------- 运行期 LD_PRELOAD 变更感知 ----------
   程序自己 setenv/putenv/unsetenv/clearenv 触及 LD_PRELOAD 后即停止接管：
   execve 不再剥离/回注它，让用户的设置真正生效，避免引起排查。 */

static int is_ld_preload_name(const char *name)
{
    return name && strcmp(name, "LD_PRELOAD") == 0;
}

int setenv(const char *name, const char *value, int overwrite)
{
    GET_REAL(setenv);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    /* 设成与目标相同的值无需停手；设成不同值才尊重之 */
    if (is_ld_preload_name(name) &&
        (!value || !g_ld_value || strcmp(value, g_ld_value) != 0))
        ld_preload_user_set = 1;
    return real(name, value, overwrite);
}

int unsetenv(const char *name)
{
    GET_REAL(unsetenv);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (is_ld_preload_name(name)) ld_preload_user_set = 1;
    return real(name);
}

int putenv(char *s)
{
    GET_REAL(putenv);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    if (s) {
        if (strncmp(s, "LD_PRELOAD=", 11) == 0) {
            if (!g_ld_value || strcmp(s + 11, g_ld_value) != 0) ld_preload_user_set = 1;
        } else if (strcmp(s, "LD_PRELOAD") == 0) {
            ld_preload_user_set = 1;
        }
    }
    return real(s);
}

int clearenv(void)
{
    GET_REAL(clearenv);
    GUARD_REAL_INT();
    REDIR_SCOPE();
    ld_preload_user_set = 1;
    return real();
}
