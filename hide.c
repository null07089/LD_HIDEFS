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
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <utime.h>
#include <unistd.h>

/* 全部配置仅来自运行时环境变量（无编译期默认）：
   HIDE_FILES="name:./rel:/abs"   隐藏名单，三种写法（冒号分隔）：
       "name"      裸名：任意路径中命中该名字即隐藏（全局）
       "./name"    相对路径：只隐藏当前工作目录下的该条目
       "/a/b/name" 绝对路径：只隐藏这一条路径
       （未设置则不隐藏任何东西）
   REDIRECT_FILES="src=dst[:src2=dst2...]"  文件重定向（用户态 bind mount）
       命中后读写/stat/open 等透明改写：src 为文件精确替换，为目录前缀替换；
       execve 是例外，不参与重定向，始终执行字面路径。
   HIDE_RESTRICTED_PATHS="/vendor:/odm:..."  受限 linker namespace 前缀
       （未设置则不限制；命中目标不注入 LD_PRELOAD）
   HIDE_SO="libfoo.so:/path/libbar.so"  隐藏 /proc/<pid>/{maps,smaps,smaps_rollup}
       中含该匹配项的行；并隐藏 /proc/<pid>/map_files 下指向这些库的符号链接。
       含 '/' 的路径项会先 realpath 绝对化（maps 里是绝对路径）；并始终自动加入
       LD_PRELOAD 自身（可按需把 hide.so 从 maps 中固定隐藏）。
   HIDE_MOUNT="/data:/mnt/secret"  隐藏 /proc/<pid>/{mounts,mountinfo,mountstat[s]}
       中挂载点等于该路径或位于其下的行。
   以上所有变量一旦设置都会被彻底隐藏（env/getenv/printenv/echo、/proc/<pid>/environ），
   动态子进程回注以继承配置，静态/受限目标剥离。
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

/* 构造期保存、供 execve 回注的 "NAME=value"（NULL 表示无需回注） */
static char *inject_ld_entry;
static char *inject_hide_entry;
static char *inject_redir_entry;
static char *inject_rpref_entry;
static char *inject_so_entry;
static char *inject_mount_entry;

/* 运行期用户/程序主动改过 LD_PRELOAD（setenv/putenv/unsetenv）后置位：
   此后不再剥离/回注 LD_PRELOAD，尊重其设置，避免“我设了却不生效”引起排查而暴露。 */
static int ld_preload_user_set;

#define MAXHIDE 64

/* 裸名条目：只存名字和长度，匹配时零分配、零系统调用 */
typedef struct {
    const char *name;
    int namelen;
} bitem;

/* 路径条目：预计算绝对路径、长度与 inode 身份，热路径直接复用 */
typedef struct {
    char *abs;         /* 规范化后的绝对路径 */
    size_t abslen;
    dev_t dev;         /* 绑定挂载别名（/data/data <-> /data/user/0）用 inode 身份匹配 */
    ino_t ino;
    int is_dir;
    int has_ident;
} pitem;

static bitem bitems[MAXHIDE];
static int nbitems;
static pitem pitems[MAXHIDE];
static int npitems;
static int has_abs;       /* 存在路径条目 */
static int has_ident;     /* 存在带 inode 身份的路径条目 */
static int has_dir_ident; /* 存在带身份的目录条目 */
static char *env_storage;

/* 防止初始化阶段 libc realpath 内部触发 readlink/stat 钩子造成重入 */
static __thread int in_hook;

/* 词法规范化：转绝对路径，去掉 . 和 .. ；
   若路径存在则再用 libc realpath 解析符号链接（/data/user/0 -> /data/data 等） */
static char *normalize(const char *path)
{
    if (!path) return NULL;
    size_t need = strlen(path) + 2;
    char cwd[4096];
    int have_cwd = 0;
    if (path[0] != '/') {
        if (getcwd(cwd, sizeof(cwd))) { need += strlen(cwd); have_cwd = 1; }
    }
    char *buf = malloc(need);
    if (!buf) return NULL;
    int pos = 0;
    if (have_cwd) {
        size_t l = strlen(cwd);
        memcpy(buf, cwd, l);
        pos = (int)l;
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
            if (pos == 0 || buf[pos - 1] != '/') buf[pos++] = '/';
            memcpy(buf + pos, p, len);
            pos += (int)len;
        }
        if (!end) break;
        p = end + 1;
    }
    if (pos == 0) buf[pos++] = '/';
    buf[pos] = '\0';

    if (!in_hook) {
        static char *(*rp)(const char *, char *) = NULL;
        if (!rp) rp = dlsym(RTLD_NEXT, "realpath");
        if (rp) {
            char rbuf[4096];
            in_hook = 1;
            char *canon = rp(buf, rbuf);
            in_hook = 0;
            if (canon) {
                free(buf);
                return strdup(canon);
            }
        }
    }
    return buf;
}

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

static void add_item(char *tok)
{
    if (!tok || !*tok) return;
    if (strchr(tok, '/')) {
        if (npitems >= MAXHIDE) return;
        char *abs = normalize(tok);
        if (!abs) return;
        pitem *it = &pitems[npitems++];
        it->abs = abs;
        it->abslen = strlen(abs);
        it->has_ident = 0;
        it->is_dir = 0;
        struct stat sb;
        if (real_stat(abs, &sb) == 0) {
            it->dev = sb.st_dev;
            it->ino = sb.st_ino;
            it->is_dir = S_ISDIR(sb.st_mode);
            it->has_ident = 1;
            has_ident = 1;
            if (it->is_dir) has_dir_ident = 1;
        }
        has_abs = 1;
    } else {
        if (nbitems >= MAXHIDE) return;
        bitems[nbitems].name = tok;
        bitems[nbitems].namelen = (int)strlen(tok);
        nbitems++;
    }
}

/* ---------- 文件重定向（用户态 bind mount） ----------
   配置 REDIRECT_FILES="src=dst[:src2=dst2...]"（冒号分隔，首个 '=' 分割）。
   命中后所有路径类系统调用的路径参数被改写：src 为文件则精确替换，为目录则前缀替换。
   与 mount --bind 类似：对调用方完全透明。 */

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
static char *redir_storage;

static void add_redirect(char *tok)
{
    if (nritems >= MAXREDIR || !tok || !*tok) return;
    char *eq = strchr(tok, '=');
    if (!eq || eq == tok || !eq[1]) {
        dprintf(2, "hide.so: REDIRECT_FILES bad entry '%s' (want src=dst)\n", tok);
        return;
    }
    *eq = '\0';
    const char *src = tok, *dst = eq + 1;
    char *s = normalize(src);
    char *d = normalize(dst);
    if (!s || !d) { free(s); free(d); return; }
    ritem *r = &ritems[nritems++];
    r->src = s;
    r->srclen = strlen(s);
    r->dst = d;
    r->dstlen = strlen(d);
    struct stat sb;
    r->is_dir = (real_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode));
}

/* ---------- 受限 linker namespace 前缀（运行时 HIDE_RESTRICTED_PATHS 配置） ---------- */

#define MAXRPRE 32

static char *rpref[MAXRPRE];
static int nrpref;
static char *rpref_storage;

static void add_rprefix(char *tok)
{
    if (nrpref >= MAXRPRE || !tok || !*tok) return;
    size_t l = strlen(tok);
    while (l > 0 && tok[l - 1] == '/') l--; /* 去掉末尾 '/'，比较时按边界处理 */
    if (!l) return;
    char *s = malloc(l + 1);
    if (!s) return;
    memcpy(s, tok, l);
    s[l] = '\0';
    rpref[nrpref++] = s;
}

/* ---------- HIDE_SO / HIDE_MOUNT：/proc 文本文件行过滤 ---------- */

#define MAXTOK 64

static char *so_tokens[MAXTOK];
static int nso;
static char *so_storage;

static char *mnt_tokens[MAXTOK];
static int nmnt;
static char *mnt_storage;

/* 把冒号分隔的存储串就地切分成 token 数组 */
static void split_tokens(char *storage, char **arr, int *n, int max)
{
    if (!storage) return;
    char *p = storage, *start = storage;
    while (*p) {
        if (*p == ':') {
            *p = '\0';
            if (*start && *n < max) arr[(*n)++] = start;
            start = p + 1;
        }
        p++;
    }
    if (*start && *n < max) arr[(*n)++] = start;
}

static int so_token_exists(const char *tok)
{
    for (int i = 0; i < nso; i++)
        if (strcmp(so_tokens[i], tok) == 0) return 1;
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
    if (so_token_exists(v)) { free(v); return; }
    so_tokens[nso++] = v;
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

__attribute__((constructor)) static void init_hidden(void)
{
    /* 本库钩了 getenv 会屏蔽 HIDE_FILES，这里必须直接取 libc 的 getenv 读取配置 */
    static char *(*real_getenv)(const char *) = NULL;
    if (!real_getenv) real_getenv = dlsym(RTLD_NEXT, "getenv");
    const char *env = real_getenv ? real_getenv("HIDE_FILES") : NULL;
    if (env && *env) {
        env_storage = strdup(env);
        /* 即使一次分配失败也不要 return，后续配置仍需解析与隐藏 */
        if (env_storage) {
            char *p = env_storage, *start = env_storage;
            while (*p) {
                if (*p == ':') { *p = '\0'; if (*start) add_item(start); start = p + 1; }
                p++;
            }
            if (*start) add_item(start);
        }
    }
    /* 未设 HIDE_FILES 则不隐藏任何东西（无内置默认名单） */

    const char *redir = real_getenv ? real_getenv("REDIRECT_FILES") : NULL;
    if (redir && *redir) {
        redir_storage = strdup(redir);
        if (redir_storage) {
            char *p = redir_storage, *start = redir_storage;
            while (*p) {
                if (*p == ':') { *p = '\0'; if (*start) add_redirect(start); start = p + 1; }
                p++;
            }
            if (*start) add_redirect(start);
        }
        /* 与 HIDE_FILES 同样处理：保存供 execve 回注，并从自身环境原地删除 */
        inject_redir_entry = make_env_entry("REDIRECT_FILES", redir);
        env_remove_inplace("REDIRECT_FILES");
    }

    const char *rp = real_getenv ? real_getenv("HIDE_RESTRICTED_PATHS") : NULL;
    if (rp && *rp) {
        rpref_storage = strdup(rp);
        if (rpref_storage) {
            char *p = rpref_storage, *start = rpref_storage;
            while (*p) {
                if (*p == ':') { *p = '\0'; if (*start) add_rprefix(start); start = p + 1; }
                p++;
            }
            if (*start) add_rprefix(start);
        }
        /* 同样彻底隐藏：保存供回注，并从自身环境原地删除 */
        inject_rpref_entry = make_env_entry("HIDE_RESTRICTED_PATHS", rp);
        env_remove_inplace("HIDE_RESTRICTED_PATHS");
    }

    const char *so = real_getenv ? real_getenv("HIDE_SO") : NULL;
    if (so && *so) {
        so_storage = strdup(so);
        if (so_storage) {
            char *p = so_storage, *start = so_storage;
            while (*p) {
                if (*p == ':') { *p = '\0'; if (*start) add_so_token(start); start = p + 1; }
                p++;
            }
            if (*start) add_so_token(start);
        }
        inject_so_entry = make_env_entry("HIDE_SO", so);
        env_remove_inplace("HIDE_SO");
    }

    const char *mnt = real_getenv ? real_getenv("HIDE_MOUNT") : NULL;
    if (mnt && *mnt) {
        mnt_storage = strdup(mnt);
        split_tokens(mnt_storage, mnt_tokens, &nmnt, MAXTOK);
        inject_mount_entry = make_env_entry("HIDE_MOUNT", mnt);
        env_remove_inplace("HIDE_MOUNT");
    }

    /* LD_PRELOAD 精确匹配值直接取当前 LD_PRELOAD（绕过本库 getenv 钩子） */
    const char *lp = real_getenv ? real_getenv("LD_PRELOAD") : NULL;
    if (lp && *lp) {
        g_ld_value = strdup(lp);
        if (g_ld_value) {
            g_ld_vlen = strlen(g_ld_value);
            g_ld_entry = make_env_entry("LD_PRELOAD", g_ld_value);
        }
        /* 固定隐藏 LD_PRELOAD 自身：解析为绝对路径加入 HIDE_SO */
        add_preload_so_tokens(lp);
    }

    /* HIDE_FILES 恒删；LD_PRELOAD 仅当值等于匹配目标时删。
       删之前保存，供 execve 给动态子进程回注（否则子进程丢掉配置/不再加载）。 */
    if (env && *env) {
        inject_hide_entry = make_env_entry("HIDE_FILES", env);
        env_remove_inplace("HIDE_FILES");
    }
    if (lp && g_ld_value && strcmp(lp, g_ld_value) == 0) {
        inject_ld_entry = make_env_entry("LD_PRELOAD", lp);
        env_remove_inplace("LD_PRELOAD");
    }
}

/* 单个目录项的裸名匹配 */
static int name_hidden(const char *name)
{
    if (!nbitems || !name) return 0;
    size_t len = strlen(name);
    for (int i = 0; i < nbitems; i++)
        if ((size_t)bitems[i].namelen == len &&
            memcmp(name, bitems[i].name, len) == 0) return 1;
    return 0;
}

/* 在整条路径的各分量中查裸名；不分配、无系统调用 */
static int bare_in_path(const char *path)
{
    if (!nbitems) return 0;
    const char *p = path;
    while (*p) {
        if (*p == '/') { p++; continue; }
        const char *end = p;
        while (*end && *end != '/') end++;
        size_t len = (size_t)(end - p);
        for (int i = 0; i < nbitems; i++)
            if ((size_t)bitems[i].namelen == len &&
                memcmp(p, bitems[i].name, len) == 0) return 1;
        if (!*end) break;
        p = end + 1;
    }
    return 0;
}

/* 词法转绝对路径并折叠 . / ..，写进调用方缓冲。
   不解析符号链接：别名由 inode 身份匹配兜底，从而彻底避开 realpath 的逐级系统调用。
   仅相对路径需要一次 getcwd。 */
static int lex_abs(const char *path, char *buf, size_t bufsz)
{
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

/* ---------- 文件重定向：路径改写 ---------- */

/* 命中重定向则把结果写入调用方缓冲 out（大小 outsz），返回 1；否则 0。
   不返回内部静态/TLS 缓冲，避免多路径改写互相覆盖与重入覆盖。 */
static int redirect_into(int dirfd, const char *path, char *out, size_t outsz)
{
    if (!nritems || !path || !*path) return 0;

    char abs[PATH_MAX];
    if (path[0] == '/' || dirfd == AT_FDCWD) {
        if (!lex_abs(path, abs, sizeof abs)) return 0;
    } else {
        char link[64], base[PATH_MAX];
        int ln = snprintf(link, sizeof link, "/proc/self/fd/%d", dirfd);
        if (ln <= 0 || ln >= (int)sizeof link) return 0;
        ssize_t n = syscall(__NR_readlinkat, AT_FDCWD, link, base, sizeof base - 1);
        if (n <= 0 || (size_t)n >= sizeof base - 1) return 0;
        base[n] = '\0';
        char joined[PATH_MAX];
        if (snprintf(joined, sizeof joined, "%s/%s", base, path) >= (int)sizeof joined) return 0;
        if (!lex_abs(joined, abs, sizeof abs)) return 0;
    }

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

/* 命中重定向则把局部 path 指向栈上 alloca 缓冲（生命周期到本函数返回）。
   每次调用独立分配，因此同一函数内多次改写、以及被调用方重入钩子都互不影响。 */
#define REDIR(path) do { \
    if (nritems) { \
        char *__rb = (char *)__builtin_alloca(PATH_MAX); \
        if (redirect_into(AT_FDCWD, (path), __rb, PATH_MAX)) (path) = __rb; \
    } \
} while (0)
#define REDIR_AT(dirfd, path) do { \
    if (nritems) { \
        char *__rb = (char *)__builtin_alloca(PATH_MAX); \
        if (redirect_into((dirfd), (path), __rb, PATH_MAX)) (path) = __rb; \
    } \
} while (0)

/* 纯字符串精确/前缀匹配（无系统调用） */
static int abs_str_match(const char *norm, size_t nlen)
{
    for (int i = 0; i < npitems; i++) {
        const pitem *it = &pitems[i];
        if (it->abslen <= nlen &&
            memcmp(norm, it->abs, it->abslen) == 0 &&
            (it->abslen == nlen || norm[it->abslen] == '/'))
            return 1;
    }
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

/* inode 精确匹配（dev+ino） */
static int ino_exact(dev_t dev, ino_t ino)
{
    for (int i = 0; i < npitems; i++) {
        const pitem *it = &pitems[i];
        if (it->has_ident && dev == it->dev && ino == it->ino) return 1;
    }
    return 0;
}

/* norm 是否位于某个隐藏目录之内：逐级向上，带线程内“干净目录”缓存 */
static int ancestor_hidden(const char *norm)
{
    if (!has_dir_ident) return 0;
    size_t nlen = strlen(norm);
    char tmp[PATH_MAX];
    if (nlen >= sizeof tmp) return 0;
    memcpy(tmp, norm, nlen + 1);
    char *stack[128];
    int ns = 0;
    size_t cur = nlen;
    while (cur > 1) {
        char *q = strrchr(tmp, '/');
        if (!q || q == tmp) break;
        *q = '\0';
        cur = (size_t)(q - tmp);
        unsigned ci = dhash(tmp) & (DCACHE - 1);
        if (clean_dirs[ci] && strcmp(clean_dirs[ci], tmp) == 0) {
            for (int k = 0; k < ns; k++) free(stack[k]);
            return 0; /* 该祖先干净 => 整支干净 */
        }
        struct stat sb;
        int hidden = 0;
        if (real_stat(tmp, &sb) == 0) {
            hidden = ino_exact(sb.st_dev, sb.st_ino);
            if (!hidden) {
                for (int i = 0; i < npitems; i++) {
                    const pitem *it = &pitems[i];
                    if (it->is_dir && it->has_ident &&
                        sb.st_dev == it->dev && sb.st_ino == it->ino) { hidden = 1; break; }
                }
            }
        }
        if (hidden) {
            for (int k = 0; k < ns; k++) free(stack[k]);
            return 1;
        }
        if (ns < (int)(sizeof stack / sizeof stack[0])) {
            char *dup = strdup(tmp);
            if (dup) stack[ns++] = dup;
        }
    }
    /* 到根都未命中：把访问过的祖先目录标记为干净 */
    for (int k = 0; k < ns; k++) clean_put_owned(stack[k]);
    return 0;
}

/* 对已词法绝对化的路径做匹配：字符串 -> 一次 stat 的 inode 精确匹配 -> 带回溯缓存的祖先检查 */
static int abs_hidden(const char *norm)
{
    size_t nlen = strlen(norm);
    if (abs_str_match(norm, nlen)) return 1;
    if (!has_ident) return 0;

    struct stat sb;
    if (real_stat(norm, &sb) != 0) return 0;
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
        for (int i = 0; i < npitems; i++)
            if (pitems[i].has_ident && pitems[i].ino == d_ino) { maybe = 1; break; }
        if (!maybe) return 0;
    }
    struct stat sb;
    if (real_stat(full, &sb) != 0) return 0;
    for (int i = 0; i < npitems; i++) {
        const pitem *it = &pitems[i];
        if (it->has_ident && sb.st_dev == it->dev && sb.st_ino == it->ino)
            return 1;
    }
    return 0;
}

/* 含 ".." 且中间夹了符号链接时，词法折叠得不到正确祖先，退回 libc realpath
   （带重入保护）以保持与原实现一致的语义；普通路径不会走到这里。 */
static int realpath_canon(const char *path, char *out)
{
    if (in_hook) return 0;
    static char *(*rp)(const char *, char *) = NULL;
    if (!rp) rp = dlsym(RTLD_NEXT, "realpath");
    if (!rp) return 0;
    in_hook = 1;
    char *c = rp(path, out);
    in_hook = 0;
    return c != NULL;
}

/* 统一入口：先零成本的裸名匹配，只有确实需要时才做词法绝对化 */
static int path_hidden(const char *path)
{
    if (!path || !*path) return 0;
    if (nbitems == 0 && npitems == 0) return 0;
    if (bare_in_path(path)) return 1;
    if (!has_abs) return 0;
    if (strstr(path, "..")) {
        char canon[PATH_MAX];
        if (realpath_canon(path, canon)) return abs_hidden(canon);
    }
    char norm[PATH_MAX];
    if (!lex_abs(path, norm, sizeof norm)) return 0;
    return abs_hidden(norm);
}

/* stat 族复用：先做零系统调用的裸名+字符串匹配；未命中时输出词法绝对路径，
   供调用方在其真实 stat 成功后直接拿 st_dev/st_ino 做 inode 校验，省掉一次 stat。 */
static int path_hidden_pre(const char *path, char *norm, size_t bufsz, int *have_norm)
{
    *have_norm = 0;
    if (!path || !*path) return 0;
    if (nbitems == 0 && npitems == 0) return 0;
    if (bare_in_path(path)) return 1;
    if (!has_abs) return 0;
    if (strstr(path, "..")) return path_hidden(path); /* 罕见：退回完整匹配 */
    if (lex_abs(path, norm, bufsz)) {
        *have_norm = 1;
        return abs_str_match(norm, strlen(norm));
    }
    return 0;
}

static int map_files_entry_hidden(const char *path);
static int path_token_match(const char *s, size_t slen, const char *tok, size_t tl);

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
    if (!real) real = next(#fn);

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
    if (!d || !path || (!has_abs && nso == 0)) return;
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
        free(copy);
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

/* 目录是否为 /proc/.../map_files */
static int is_map_files_dir(const char *dp)
{
    static const char suf[] = "/map_files";
    size_t l = strlen(dp), sl = sizeof(suf) - 1;
    return l >= sl && memcmp(dp + l - sl, suf, sl) == 0;
}

/* 读取 full 这个 map_files 符号链接的目标，判断是否命中 HIDE_SO */
static int so_target_hidden(const char *full)
{
    char tgt[PATH_MAX];
    ssize_t n = syscall(__NR_readlinkat, AT_FDCWD, full, tgt, sizeof tgt - 1);
    if (n <= 0) return 0;
    tgt[n] = '\0';
    for (int i = 0; i < nso; i++)
        if (path_token_match(tgt, (size_t)n, so_tokens[i], strlen(so_tokens[i]))) return 1;
    return 0;
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

/* ---------- 目录列举 ---------- */

struct dirent *readdir(DIR *dirp)
{
    GET_REAL(readdir);
    if (!real) { errno = ENOSYS; return NULL; }
    struct dirent *d;
    if (!has_abs && nso == 0) { /* 只有裸名：零分配 */
        while ((d = real(dirp)) != NULL)
            if (!name_hidden(d->d_name)) return d;
        return NULL;
    }
    while ((d = real(dirp)) != NULL) {
        if (name_hidden(d->d_name)) continue;
        const char *dp = dir_path(dirp);
        if (dp) {
            char full[PATH_MAX];
            if (join_path(full, sizeof full, dp, d->d_name)) {
                if (has_abs && entry_hidden(full, d->d_ino)) continue;
                if (nso && is_map_files_dir(dp) && so_target_hidden(full)) continue;
            }
        }
        return d;
    }
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp)
{
    GET_REAL(readdir64);
    if (!real) { errno = ENOSYS; return NULL; }
    struct dirent64 *d;
    if (!has_abs && nso == 0) {
        while ((d = real(dirp)) != NULL)
            if (!name_hidden(d->d_name)) return d;
        return NULL;
    }
    while ((d = real(dirp)) != NULL) {
        if (name_hidden(d->d_name)) continue;
        const char *dp = dir_path(dirp);
        if (dp) {
            char full[PATH_MAX];
            if (join_path(full, sizeof full, dp, d->d_name)) {
                if (has_abs && entry_hidden(full, d->d_ino)) continue;
                if (nso && is_map_files_dir(dp) && so_target_hidden(full)) continue;
            }
        }
        return d;
    }
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
    REDIR(dir);
    if (path_hidden(dir)) { errno = ENOENT; return -1; }
    int n = real(dir, namelist, filter, compar);
    if (n <= 0 || !namelist || !*namelist) return n;
    char dbuf[PATH_MAX];
    const char *dp = ((has_abs || nso) && lex_abs(dir, dbuf, sizeof dbuf)) ? dbuf : NULL;
    int kept = 0;
    for (int i = 0; i < n; i++) {
        struct dirent *d = (*namelist)[i];
        if (!d) continue;
        int hid = name_hidden(d->d_name);
        if (!hid && dp) {
            char full[PATH_MAX];
            if (join_path(full, sizeof full, dp, d->d_name)) {
                if (has_abs && entry_hidden(full, d->d_ino)) hid = 1;
                else if (nso && is_map_files_dir(dp) && so_target_hidden(full)) hid = 1;
            }
        }
        if (hid) free(d);
        else (*namelist)[kept++] = d;
    }
    if (kept != n) {
        struct dirent **nn = realloc(*namelist,
            (size_t)(kept ? kept : 1) * sizeof(struct dirent *));
        if (nn) *namelist = nn;
    }
    return kept;
}

/* ---------- 属性检查 ---------- */

int stat(const char *path, struct stat *buf)
{
    GET_REAL(stat);
    REDIR(path);
    char norm[PATH_MAX]; int have_norm = 0;
    if (path_hidden_pre(path, norm, sizeof norm, &have_norm) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int r = real(path, buf);
    if (r == 0 && has_ident &&
        (ino_exact(buf->st_dev, buf->st_ino) ||
         (has_dir_ident && have_norm && ancestor_hidden(norm)))) {
        errno = ENOENT; return -1;
    }
    return r;
}

int stat64(const char *path, struct stat64 *buf)
{
    GET_REAL(stat64);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR(path);
    char norm[PATH_MAX]; int have_norm = 0;
    if (path_hidden_pre(path, norm, sizeof norm, &have_norm) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int r = real(path, buf);
    if (r == 0 && has_ident &&
        (ino_exact(buf->st_dev, buf->st_ino) ||
         (has_dir_ident && have_norm && ancestor_hidden(norm)))) {
        errno = ENOENT; return -1;
    }
    return r;
}

int lstat(const char *path, struct stat *buf)
{
    GET_REAL(lstat);
    REDIR(path);
    char norm[PATH_MAX]; int have_norm = 0;
    if (path_hidden_pre(path, norm, sizeof norm, &have_norm) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int r = real(path, buf);
    if (r == 0 && has_ident &&
        (ino_exact(buf->st_dev, buf->st_ino) ||
         (has_dir_ident && have_norm && ancestor_hidden(norm)))) {
        errno = ENOENT; return -1;
    }
    return r;
}

int lstat64(const char *path, struct stat64 *buf)
{
    GET_REAL(lstat64);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR(path);
    char norm[PATH_MAX]; int have_norm = 0;
    if (path_hidden_pre(path, norm, sizeof norm, &have_norm) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int r = real(path, buf);
    if (r == 0 && has_ident &&
        (ino_exact(buf->st_dev, buf->st_ino) ||
         (has_dir_ident && have_norm && ancestor_hidden(norm)))) {
        errno = ENOENT; return -1;
    }
    return r;
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags)
{
    GET_REAL(fstatat);
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(dirfd, path, buf, flags);
}

int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags)
{
    GET_REAL(fstatat64);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(dirfd, path, buf, flags);
}

int statx(int dirfd, const char *path, int flags, unsigned int mask, struct statx *buf)
{
    GET_REAL(statx);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(dirfd, path, flags, mask, buf);
}

int access(const char *path, int mode)
{
    GET_REAL(access);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, mode);
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    GET_REAL(faccessat);
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(dirfd, path, mode, flags);
}

char *realpath(const char *path, char *resolved)
{
    GET_REAL(realpath);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return NULL; }
    return real(path, resolved);
}

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

/* map_files 下的符号链接若指向被 HIDE_SO 命中的库则视为不存在 */
static int map_link_hidden(const char *path, const char *buf, ssize_t r)
{
    if (nso == 0 || r <= 0 || !strstr(path, "/map_files/")) return 0;
    size_t n = (size_t)r;
    if (n >= PATH_MAX) n = PATH_MAX - 1;
    char tgt[PATH_MAX];
    memcpy(tgt, buf, n);
    tgt[n] = '\0';
    for (int i = 0; i < nso; i++)
        if (path_token_match(tgt, n, so_tokens[i], strlen(so_tokens[i]))) return 1;
    return 0;
}

/* 路径位于 /proc/.../map_files/<addr> 且其符号链接目标命中 HIDE_SO。
   用于 open/stat/access 等按地址直接访问时也视为不存在。 */
static int map_files_entry_hidden(const char *path)
{
    if (nso == 0 || !path || !strstr(path, "/map_files/")) return 0;
    char tgt[PATH_MAX];
    ssize_t n = syscall(__NR_readlinkat, AT_FDCWD, path, tgt, sizeof tgt - 1);
    if (n <= 0) return 0;
    tgt[n] = '\0';
    for (int i = 0; i < nso; i++)
        if (path_token_match(tgt, (size_t)n, so_tokens[i], strlen(so_tokens[i]))) return 1;
    return 0;
}

ssize_t readlink(const char *path, char *buf, size_t size)
{
    GET_REAL(readlink);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    ssize_t r = real(path, buf, size);
    if (map_link_hidden(path, buf, r)) { errno = ENOENT; return -1; }
    return r;
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t size)
{
    GET_REAL(readlinkat);
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    ssize_t r = real(dirfd, path, buf, size);
    if (map_link_hidden(path, buf, r)) { errno = ENOENT; return -1; }
    return r;
}

/* ---------- /proc/<pid>/environ 脱敏 ----------
   进程读取自身（或同 pid 的）environ 时，抹掉 LD_PRELOAD=<目标> 与 HIDE_FILES=*。
   environ 由内核在 read 时生成，无法逐块改写，故拦截 open：一次性读出真实内容、
   脱敏后写入 memfd，返回该 fd，后续 read/lseek/fstat/mmap 均正常。 */

static int raw_open_ro(const char *path);
static ssize_t raw_read(int fd, void *buf, size_t n);
static off_t raw_seek(int fd, off_t off);

static int raw_memfd(const char *name, unsigned int flags)
{
#ifdef __NR_memfd_create
    return (int)syscall(__NR_memfd_create, name, flags);
#else
    (void)name; (void)flags; errno = ENOSYS; return -1;
#endif
}

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
    for (int i = 0; i < nso; i++)
        if (path_token_match(line, len, so_tokens[i], strlen(so_tokens[i]))) return 1;
    return 0;
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
        size_t tl = strlen(mnt_tokens[i]);
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
        size_t tl = strlen(mnt_tokens[i]);
        if (pl == tl && memcmp(norm, mnt_tokens[i], tl) == 0) return 1;
        if (pl > tl && memcmp(norm, mnt_tokens[i], tl) == 0 && norm[tl] == '/') return 1;
    }
    return 0;
}

/* 返回 1 表示已处理（*out 为结果 fd，失败为 -1）；返回 0 表示不处理该路径 */
static ssize_t raw_write(int fd, const void *buf, size_t n)
{
#ifdef __NR_write
    return syscall(__NR_write, fd, buf, n);
#else
    return write(fd, buf, n);
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

/* 单条是否应删除 */
static int seg_drop(const char *s, size_t n, int kind, int midx)
{
    if (kind == PK_ENVIRON) {
        const size_t lp = g_ld_entry ? 11 + g_ld_vlen : 0;
        return (lp && n == lp && memcmp(s, g_ld_entry, lp) == 0) ||
               (n >= 11 && memcmp(s, "HIDE_FILES=", 11) == 0) ||
               (n >= 15 && memcmp(s, "REDIRECT_FILES=", 15) == 0) ||
               (n >= 22 && memcmp(s, "HIDE_RESTRICTED_PATHS=", 22) == 0) ||
               (n >= 8 && memcmp(s, "HIDE_SO=", 8) == 0) ||
               (n >= 11 && memcmp(s, "HIDE_MOUNT=", 11) == 0);
    }
    if (kind == PK_SO) return so_line_drop(s, n);
    return mount_line_drop(s, n, midx);
}

/* 流式过滤 /proc 文本：边读边写 memfd，只保留一个不完整尾段，避免整文件双缓冲 */
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
        if (!errno) errno = EIO;
        *out = -1;
        return 1;
    }

    char chunk[65536];
    char *carry = NULL;
    size_t clen = 0, ccap = 0;
    const char sep = (kind == PK_ENVIRON) ? '\0' : '\n';
    const int midx = (kind == PK_MOUNT) ? mount_field_index(path) : 0;
    int ok = 1;

    for (;;) {
        ssize_t r = raw_read(rfd, chunk, sizeof chunk);
        if (r < 0) { ok = 0; break; }
        if (r == 0) break;
        if (clen + (size_t)r > ccap) {
            size_t nc = ccap ? ccap : 8192;
            while (nc < clen + (size_t)r) nc *= 2;
            char *nb = realloc(carry, nc);
            if (!nb) { ok = 0; errno = ENOMEM; break; }
            carry = nb; ccap = nc;
        }
        memcpy(carry + clen, chunk, (size_t)r);
        clen += (size_t)r;

        size_t start = 0;
        for (size_t i = 0; i < clen; i++) {
            if (carry[i] != sep) continue;
            size_t llen = i - start;
            if (!seg_drop(carry + start, llen, kind, midx) &&
                (write_all(mfd, carry + start, llen) < 0 ||
                 write_all(mfd, &sep, 1) < 0)) { ok = 0; break; }
            start = i + 1;
        }
        if (!ok) break;
        if (start) { memmove(carry, carry + start, clen - start); clen -= start; }
        if (clen > (1u << 20)) { /* 防御异常长条目 */
            if (write_all(mfd, carry, clen) < 0) { ok = 0; break; }
            clen = 0;
        }
    }
    if (ok && clen) {
        if (!seg_drop(carry, clen, kind, midx) &&
            (write_all(mfd, carry, clen) < 0 ||
             (sep == '\0' && write_all(mfd, &sep, 1) < 0))) ok = 0;
    }
    free(carry);
    close(rfd);
    if (!ok) {
        close(mfd);
        if (!errno) errno = EIO;
        *out = -1;
        return 1;
    }
    raw_seek(mfd, 0);
    *out = mfd;
    return 1;
}

/* ---------- 文件系统信息：被隐藏的挂载点也视为不存在 ---------- */

int statfs(const char *path, struct statfs *buf)
{
    GET_REAL(statfs);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path) || mount_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return real(path, buf);
}

int statfs64(const char *path, struct statfs64 *buf)
{
    GET_REAL(statfs64);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path) || mount_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return real(path, buf);
}

int statvfs(const char *path, struct statvfs *buf)
{
    GET_REAL(statvfs);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path) || mount_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return real(path, buf);
}

int statvfs64(const char *path, struct statvfs64 *buf)
{
    GET_REAL(statvfs64);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path) || mount_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return real(path, buf);
}

/* ---------- 打开/读取 ---------- */

int open(const char *path, int flags, ...)
{
    GET_REAL(open);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int fd;
    if (handle_proc_file(path, flags, &fd)) return fd;
    va_list ap;
    va_start(ap, flags);
    int mode = ((flags & O_CREAT) || (flags & O_TMPFILE)) ? va_arg(ap, int) : 0;
    va_end(ap);
    return real(path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
    GET_REAL(open64);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int fd;
    if (handle_proc_file(path, flags, &fd)) return fd;
    va_list ap;
    va_start(ap, flags);
    int mode = ((flags & O_CREAT) || (flags & O_TMPFILE)) ? va_arg(ap, int) : 0;
    va_end(ap);
    return real(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    GET_REAL(openat);
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int fd;
    if (handle_proc_file(path, flags, &fd)) return fd;
    va_list ap;
    va_start(ap, flags);
    int mode = ((flags & O_CREAT) || (flags & O_TMPFILE)) ? va_arg(ap, int) : 0;
    va_end(ap);
    return real(dirfd, path, flags, mode);
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    GET_REAL(openat64);
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int fd;
    if (handle_proc_file(path, flags, &fd)) return fd;
    va_list ap;
    va_start(ap, flags);
    int mode = ((flags & O_CREAT) || (flags & O_TMPFILE)) ? va_arg(ap, int) : 0;
    va_end(ap);
    return real(dirfd, path, flags, mode);
}

int __open_2(const char *path, int flags)
{
    GET_REAL(__open_2);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int fd;
    if (handle_proc_file(path, flags, &fd)) return fd;
    return real(path, flags);
}

int __openat_2(int dirfd, const char *path, int flags)
{
    GET_REAL(__openat_2);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    int fd;
    if (handle_proc_file(path, flags, &fd)) return fd;
    return real(dirfd, path, flags);
}

ssize_t __readlinkat_chk(int dirfd, const char *path, char *buf, size_t bufsiz, size_t buflen)
{
    GET_REAL(__readlinkat_chk);
    if (!real) { errno = ENOSYS; return -1; }
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    ssize_t r = real(dirfd, path, buf, bufsiz, buflen);
    if (map_link_hidden(path, buf, r)) { errno = ENOENT; return -1; }
    return r;
}

int creat(const char *path, mode_t mode)
{
    GET_REAL(creat);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, mode);
}

int creat64(const char *path, mode_t mode)
{
    GET_REAL(creat64);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, mode);
}

FILE *fopen(const char *path, const char *mode)
{
    GET_REAL(fopen);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return NULL; }
    return real(path, mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    GET_REAL(fopen64);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return NULL; }
    return real(path, mode);
}

FILE *freopen(const char *path, const char *mode, FILE *stream)
{
    GET_REAL(freopen);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return NULL; }
    return real(path, mode, stream);
}

FILE *freopen64(const char *path, const char *mode, FILE *stream)
{
    GET_REAL(freopen64);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return NULL; }
    return real(path, mode, stream);
}

DIR *opendir(const char *path)
{
    GET_REAL(opendir);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return NULL; }
    DIR *d = real(path);
    if (d) dir_record(d, path);
    return d;
}

DIR *fdopendir(int fd)
{
    GET_REAL(fdopendir);
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    char target[4096];
    ssize_t n = readlink(link, target, sizeof(target) - 1);
    if (n > 0) {
        target[n] = '\0';
        if (path_hidden(target)) { errno = ENOENT; return NULL; }
        DIR *d = real(fd);
        if (d) dir_record(d, target);
        return d;
    }
    return real(fd);
}

int closedir(DIR *dirp)
{
    GET_REAL(closedir);
    if (dirp) dir_forget(dirp);
    return real(dirp);
}

/* ---------- 保护：改名/删除/改属性一律 ENOENT ---------- */

int unlink(const char *path)
{
    GET_REAL(unlink);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path);
}

int unlinkat(int dirfd, const char *path, int flags)
{
    GET_REAL(unlinkat);
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(dirfd, path, flags);
}

int remove(const char *path)
{
    GET_REAL(remove);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path);
}

int rmdir(const char *path)
{
    GET_REAL(rmdir);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path);
}

int rename(const char *oldp, const char *newp)
{
    GET_REAL(rename);
    REDIR(oldp);
    REDIR(newp);
    if (path_hidden(oldp) || path_hidden(newp)) { errno = ENOENT; return -1; }
    return real(oldp, newp);
}

int renameat(int odirfd, const char *oldp, int ndirfd, const char *newp)
{
    GET_REAL(renameat);
    REDIR_AT(odirfd, oldp);
    REDIR_AT(ndirfd, newp);
    if (path_hidden(oldp) || path_hidden(newp)) { errno = ENOENT; return -1; }
    return real(odirfd, oldp, ndirfd, newp);
}

int renameat2(int odirfd, const char *oldp, int ndirfd, const char *newp, unsigned int flags)
{
    GET_REAL(renameat2);
    REDIR_AT(odirfd, oldp);
    REDIR_AT(ndirfd, newp);
    if (path_hidden(oldp) || path_hidden(newp)) { errno = ENOENT; return -1; }
    return real(odirfd, oldp, ndirfd, newp, flags);
}

int chmod(const char *path, mode_t mode)
{
    GET_REAL(chmod);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, mode);
}

int fchmodat(int dirfd, const char *path, mode_t mode, int flags)
{
    GET_REAL(fchmodat);
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(dirfd, path, mode, flags);
}

int chown(const char *path, uid_t owner, gid_t group)
{
    GET_REAL(chown);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, owner, group);
}

int lchown(const char *path, uid_t owner, gid_t group)
{
    GET_REAL(lchown);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, owner, group);
}

int utimensat(int dirfd, const char *path, const struct timespec times[2], int flags)
{
    GET_REAL(utimensat);
    REDIR_AT(dirfd, path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(dirfd, path, times, flags);
}

int utimes(const char *path, const struct timeval times[2])
{
    GET_REAL(utimes);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, times);
}

int utime(const char *path, const struct utimbuf *times)
{
    GET_REAL(utime);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, times);
}

int truncate(const char *path, off_t length)
{
    GET_REAL(truncate);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, length);
}

int truncate64(const char *path, off64_t length)
{
    GET_REAL(truncate64);
    REDIR(path);
    if (path_hidden(path) || map_files_entry_hidden(path)) { errno = ENOENT; return -1; }
    return real(path, length);
}

int link(const char *oldp, const char *newp)
{
    GET_REAL(link);
    REDIR(oldp);
    REDIR(newp);
    if (path_hidden(oldp) || path_hidden(newp)) { errno = ENOENT; return -1; }
    return real(oldp, newp);
}

int linkat(int odirfd, const char *oldp, int ndirfd, const char *newp, int flags)
{
    GET_REAL(linkat);
    REDIR_AT(odirfd, oldp);
    REDIR_AT(ndirfd, newp);
    if (path_hidden(oldp) || path_hidden(newp)) { errno = ENOENT; return -1; }
    return real(odirfd, oldp, ndirfd, newp, flags);
}

int symlink(const char *target, const char *linkpath)
{
    GET_REAL(symlink);
    REDIR(linkpath);
    if (path_hidden(linkpath)) { errno = EEXIST; return -1; }
    return real(target, linkpath);
}

int symlinkat(const char *target, int dirfd, const char *linkpath)
{
    GET_REAL(symlinkat);
    REDIR_AT(dirfd, linkpath);
    if (path_hidden(linkpath)) { errno = EEXIST; return -1; }
    return real(target, dirfd, linkpath);
}

int mkdir(const char *path, mode_t mode)
{
    GET_REAL(mkdir);
    REDIR(path);
    if (path_hidden(path)) { errno = EEXIST; return -1; }
    return real(path, mode);
}

int mkdirat(int dirfd, const char *path, mode_t mode)
{
    GET_REAL(mkdirat);
    REDIR_AT(dirfd, path);
    if (path_hidden(path)) { errno = EEXIST; return -1; }
    return real(dirfd, path, mode);
}

/* ---------- execve ----------
   静态链接程序执行前卸除 LD_PRELOAD 与 HIDE_FILES：hide.so 依赖动态链接器注入；
   静态链接（含静态 PIE）的 ELF 没有 PT_INTERP，动态链接器不会介入，LD_PRELOAD
   对其无效。若继续传给被 exec 的程序会污染其子进程环境，也会把隐藏名单
   （HIDE_FILES）泄露出去。故读 ELF 程序头判断是否含 PT_INTERP：没有则剥掉 envp
   里的 LD_PRELOAD 与 HIDE_FILES 再 exec。
   bionic 的 execvp/execvpe/fexecve 最终都经 PLT 调用 execve，故只需钩 execve。 */

/* 绕过本库 open 钩子，直接用系统调用打开待执行文件 */
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
    if (raw_read(fd, hdr, 16) != 16) { close(fd); return 0; }

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
    if (hdr[4] == 2) { /* ELF64 */
        if (raw_read(fd, hdr + 16, 48) != 48) { close(fd); return 0; }
        phoff = rl64(hdr + 32);
        phentsize = rl16(hdr + 54);
        phnum = rl16(hdr + 56);
    } else if (hdr[4] == 1) { /* ELF32 */
        if (raw_read(fd, hdr + 16, 36) != 36) { close(fd); return 0; }
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

static const char *envp_get(char *const envp[], const char *name)
{
    if (!envp) return NULL;
    size_t n = strlen(name);
    for (int i = 0; envp[i]; i++)
        if (strncmp(envp[i], name, n) == 0 && envp[i][n] == '=') return envp[i] + n + 1;
    return NULL;
}

static int envp_has_var(char *const envp[], const char *name)
{
    return envp_get(envp, name) != NULL;
}

/* 按需重写 envp：剥掉指定的环境变量条目，再追加要回注的条目。
   无需改动时原样返回；改动时返回新数组（调用方负责 free）。 */
static int env_is(const char *e, const char *name, size_t n)
{
    return strncmp(e, name, n) == 0 && e[n] == '=';
}

typedef struct {
    const char *name;
    size_t nlen;
    int strip;
    const char *add;
} envop;

/* 按需重写 envp：strip 指定的条目剥掉，add 指定的条目追加。
   无需改动时原样返回；改动时返回新数组（调用方负责 free）。 */
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
    if (!nv) return envp;
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

/* 全部需要彻底隐藏的运行时配置变量（名称 + 长度） */
#define N_CFG_VARS 6
static const envop cfg_strip_all[N_CFG_VARS] = {
    { "LD_PRELOAD", 10, 1, NULL },
    { "HIDE_FILES", 10, 1, NULL },
    { "REDIRECT_FILES", 14, 1, NULL },
    { "HIDE_RESTRICTED_PATHS", 21, 1, NULL },
    { "HIDE_SO", 7, 1, NULL },
    { "HIDE_MOUNT", 10, 1, NULL },
};

/* 受限 linker namespace 的可执行文件（如 /vendor、/odm、/product）不允许从 /data
   注入，否则报 "library ... is not accessible for the namespace" 并致命退出。
   前缀列表由运行时 HIDE_RESTRICTED_PATHS 提供（冒号分隔）；未配置则不限制。
   对命中目标一律剥离 LD_PRELOAD/HIDE_FILES/REDIRECT_FILES，不注入。 */
static int path_is_restricted_prefix(const char *p)
{
    for (int i = 0; i < nrpref; i++) {
        size_t l = strlen(rpref[i]);
        if (strncmp(p, rpref[i], l) == 0 && (p[l] == '\0' || p[l] == '/')) return 1;
    }
    return 0;
}

static int target_linker_restricted(const char *path)
{
    if (!path || !*path) return 0;
    char buf[PATH_MAX];
    const char *p = path;
    if (path[0] != '/') {
        if (!lex_abs(path, buf, sizeof buf)) return 0;
        p = buf;
    }
    if (path_is_restricted_prefix(p)) return 1;
    /* 兜底：/system/bin/sh 之类可能是指向 /vendor 的符号链接，按真实路径再判。
       仅对可能含此类符号链接的分区做 realpath，避免 /data 热路径每次都解析。 */
    if (strncmp(p, "/system/", 8) == 0 || strncmp(p, "/system_ext/", 12) == 0 ||
        strncmp(p, "/product/", 9) == 0 || strncmp(p, "/apex/", 6) == 0) {
        char canon[PATH_MAX];
        if (realpath_canon(path, canon) && path_is_restricted_prefix(canon)) return 1;
    }
    return 0;
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    GET_REAL(execve);

    /* 例外：execve 不参与重定向，始终执行字面路径（因此也能执行被隐藏的原文件）。
       重定向只作用于 stat/open/read/write 等读写类操作。 */

    int has = envp_has_var(envp, "LD_PRELOAD") || envp_has_var(envp, "HIDE_FILES") ||
              envp_has_var(envp, "REDIRECT_FILES") ||
              envp_has_var(envp, "HIDE_RESTRICTED_PATHS") ||
              envp_has_var(envp, "HIDE_SO") || envp_has_var(envp, "HIDE_MOUNT");
    if (!has && !inject_ld_entry && !inject_hide_entry && !inject_redir_entry &&
        !inject_rpref_entry && !inject_so_entry && !inject_mount_entry)
        return real(path, argv, envp);

    /* 受限 namespace 目标：任何模式都剥离全部配置，避免致命加载错误 */
    if (target_linker_restricted(path)) {
        char *const *nenv = build_env(envp, cfg_strip_all, N_CFG_VARS);
        int r = real(path, argv, nenv);
        if (nenv != envp) free((void *)nenv);
        return r;
    }

    /* 用户运行期自己改过 LD_PRELOAD（setenv/putenv/unsetenv，或直接改了 envp 如 bash export），
       或 envp 里 LD_PRELOAD 的值不等于目标：不再接管它（不剥不回注），
       其余配置仍剥掉，以免泄露。 */
    const char *env_ld = envp_get(envp, "LD_PRELOAD");
    if (ld_preload_user_set ||
        (env_ld && (!g_ld_value || strcmp(env_ld, g_ld_value) != 0))) {
        static const envop ops[N_CFG_VARS] = {
            { "LD_PRELOAD", 10, 0, NULL },
            { "HIDE_FILES", 10, 1, NULL },
            { "REDIRECT_FILES", 14, 1, NULL },
            { "HIDE_RESTRICTED_PATHS", 21, 1, NULL },
            { "HIDE_SO", 7, 1, NULL },
            { "HIDE_MOUNT", 10, 1, NULL },
        };
        char *const *nenv = build_env(envp, ops, N_CFG_VARS);
        int r = real(path, argv, nenv);
        if (nenv != envp) free((void *)nenv);
        return r;
    }

    if (elf_is_static_depth(path, 0) || !inject_ld_entry) {
        /* 静态目标，或本进程并非经 LD_PRELOAD 加载（子进程不会加载 hide.so）：
           一律只剥离不回注，避免配置泄露。 */
        char *const *nenv = build_env(envp, cfg_strip_all, N_CFG_VARS);
        int r = real(path, argv, nenv);
        if (nenv != envp) free((void *)nenv);
        return r;
    }
    /* 动态目标且能保证子进程加载 hide.so：剥掉后按需回注，保证配置一致。 */
    const envop ops[N_CFG_VARS] = {
        { "LD_PRELOAD", 10, inject_ld_entry ? 1 : 0, inject_ld_entry },
        { "HIDE_FILES", 10, 1, inject_hide_entry },
        { "REDIRECT_FILES", 14, 1, inject_redir_entry },
        { "HIDE_RESTRICTED_PATHS", 21, 1, inject_rpref_entry },
        { "HIDE_SO", 7, 1, inject_so_entry },
        { "HIDE_MOUNT", 10, 1, inject_mount_entry },
    };
    char *const *nenv = build_env(envp, ops, N_CFG_VARS);
    int r = real(path, argv, nenv);
    if (nenv != envp) free((void *)nenv);
    return r;
}

/* ---------- getenv 脱敏 ----------
   getenv("HIDE_FILES") 恒为 NULL；getenv("LD_PRELOAD") 的值等于目标时返回 NULL，
   否则原样返回。注意 init_hidden 已绕过本钩子直接取 libc getenv 读配置。 */
char *getenv(const char *name)
{
    GET_REAL(getenv);
    if (name) {
        /* 所有运行时配置变量一律不可见 */
        if (strcmp(name, "HIDE_FILES") == 0) return NULL;
        if (strcmp(name, "REDIRECT_FILES") == 0) return NULL;
        if (strcmp(name, "HIDE_RESTRICTED_PATHS") == 0) return NULL;
        if (strcmp(name, "HIDE_SO") == 0) return NULL;
        if (strcmp(name, "HIDE_MOUNT") == 0) return NULL;
        if (strcmp(name, "LD_PRELOAD") == 0) {
            char *v = real(name);
            if (v && g_ld_value && strcmp(v, g_ld_value) == 0) return NULL;
            return v;
        }
    }
    return real(name);
}

/* secure_getenv：本机 bionic 无此符号；存在时按同样规则脱敏，缺失时退回本库 getenv */
char *secure_getenv(const char *name)
{
    GET_REAL(secure_getenv);
    if (!real) return getenv(name);
    if (name) {
        if (strcmp(name, "HIDE_FILES") == 0) return NULL;
        if (strcmp(name, "REDIRECT_FILES") == 0) return NULL;
        if (strcmp(name, "HIDE_RESTRICTED_PATHS") == 0) return NULL;
        if (strcmp(name, "HIDE_SO") == 0) return NULL;
        if (strcmp(name, "HIDE_MOUNT") == 0) return NULL;
        if (strcmp(name, "LD_PRELOAD") == 0) {
            char *v = real(name);
            if (v && g_ld_value && strcmp(v, g_ld_value) == 0) return NULL;
            return v;
        }
    }
    return real(name);
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
    /* 设成与目标相同的值无需停手；设成不同值才尊重之 */
    if (is_ld_preload_name(name) &&
        (!value || !g_ld_value || strcmp(value, g_ld_value) != 0))
        ld_preload_user_set = 1;
    return real(name, value, overwrite);
}

int unsetenv(const char *name)
{
    GET_REAL(unsetenv);
    if (is_ld_preload_name(name)) ld_preload_user_set = 1;
    return real(name);
}

int putenv(char *s)
{
    GET_REAL(putenv);
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
    ld_preload_user_set = 1;
    return real();
}
