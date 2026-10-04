# 设计文档（Design）

[← 返回 README](../README.md) · [使用文档](USAGE.md) · [English usage](USAGE.en.md)

本文说明 `hide.so` 的内部实现：钩子机制、匹配算法、`/proc` 脱敏、环境自隐藏、性能与并发。

---

## 1. 总体结构

单文件 `hide.c`，编译为动态库。核心组件：

```
init_hidden()                 构造函数：扫描 environ 解析配置、环境自隐藏、LD_PRELOAD 自隐藏
add_item / add_allow          解析 HIDE_FILES / ALLOW_ACCESS（仅绝对路径）
path_hidden / abs_hidden      隐藏匹配（字符串 / inode / 祖先，带回溯缓存）
access_allowed                放行名单匹配（fstatat/faccessat/execve 专用）
redirect_into / redirect_at   重定向匹配（bind 风格，含 dirfd 解析与 TLS 作用域）
handle_proc_file              /proc 文本脱敏（流式 → memfd）
env_rebuild / build_env       execve 环境重写（剥离/保留/回注）
GET_REAL / next               RTLD_NEXT 懒加载；W_* 宏生成路径类钩子
```

所有对外函数以 `LD_PRELOAD` 方式**插桩** libc 包装函数；真实实现由 `dlsym(RTLD_NEXT, ...)`
取得（失败降级为 `ENOSYS`，不退出）。

## 2. 钩子清单

- 属性：`stat/stat64/lstat/lstat64/fstatat/fstatat64/statx/access/faccessat`
- 打开：`open/open64/openat/openat64/__open_2/__openat_2/creat/creat64/fopen/fopen64/freopen/freopen64/opendir/fdopendir/closedir`
- 目录：`readdir/readdir64/scandir`
- 链接：`readlink/readlinkat/__readlinkat_chk/symlink/symlinkat/link/linkat`
- 保护写：`unlink/unlinkat/remove/rmdir/rename/renameat/renameat2/chmod/fchmodat/chown/lchown/utimes/utime/utimensat/truncate/truncate64/mkdir/mkdirat`
- 扩展属性：`getxattr/lgetxattr/listxattr/llistxattr/setxattr/lsetxattr/removexattr/lremovexattr`
- 文件系统信息：`statfs/statfs64/statvfs/statvfs64/umount/umount2`
- 进程：`execve`
- 环境：`getenv/secure_getenv/setenv/unsetenv/putenv/clearenv`

> 约定：路径类钩子按 `REDIR`（重定向）→ 隐藏判定 → 真实调用的顺序处理；命中重定向时本次
> 跳过隐藏判定（`fstatat`/`faccessat` 另叠加 `ALLOW_ACCESS` 放行，`execve` 见 §7）。
> 大部分钩子由 `W_INT_PATH*`/`W_INT_AT*`/`W_TWO_*`/`W_STAT_IMPL`/`W_STATVFS`/`W_OPEN*`/
> `W_XATTR*`/`W_FOPEN` 宏生成，保证行为一致。

## 3. 隐藏匹配（HIDE_FILES）

初始化时把**仅绝对路径**的条目 `normalize()` 规范化（存在则 `realpath`，否则词法绝对化），
登记为 `pitem`；能取到 `stat` 的条目另外把 `st_dev/st_ino` 登记进独立的身份表，避免热路径
逐条判 `has_ident`。非绝对路径条目直接告警丢弃。条目按路径长度升序排序，前缀匹配可提前退出。

运行期 `path_hidden()`：

1. 若当前正处于某次重定向且路径恰为重定向目标，直接放行（本次豁免）；
2. 零分配字符串精确/前缀匹配（`abs_str_match`，按长度排序提前 break）；
3. 必要时词法绝对化（`lex_abs`：无 `.`/`..` 的绝对路径走零拷贝快路径，相对路径一次 `getcwd`）；
4. 一次直连 `fstatat` 做 inode 身份匹配（跨绑定挂载别名）；
5. 目录条目逐级向上比较父目录 inode（`cuts` 存前缀长度，全程零分配），并用**线程内
   “干净目录”缓存**提前终止；只有确认整支干净后才分配缓存条目。

`readdir/scandir` 使用 `dirent.d_ino` 先做廉价过滤，命中候选才 `stat`；`DIR*` 映射满时按
FIFO 淘汰最旧条目，保证最近打开的目录仍可跟踪。

`ALLOW_ACCESS` 只影响 `fstatat`/`fstatat64`/`faccessat` 及 `execve`：字面路径命中名单即可豁免
隐藏；目录条目对子树生效。

## 4. 重定向（REDIRECT_FILES）

`redirect_into()` 先用 `resolve_at()` 把路径解析为词法绝对路径：绝对路径直接词法化；相对路径
在 `dirfd != AT_FDCWD` 时经 `/proc/self/fd/<dirfd>` 取目录再拼接，与内核 dirfd 语义一致。
随后与规则 `src` 比较：

- 文件：精确相等 → 命中；
- 目录：`src` + `/` 前缀 → 用 `dst` + 余部替换。

命中结果写入**调用方栈上 `alloca` 缓冲**（`REDIR` 宏），每次调用独立分配，因此同一函数内
多次改写（如 `rename(old,new)`）互不覆盖，被调用方内部重入钩子也不会破坏正在使用的路径。
第一条命中的规则生效，不链式。

`redirect_at()` 还会在 TLS 中记录“本次重定向目标路径 + inode 身份 + 深度”，并用
`REDIR_SCOPE()`（`cleanup` 属性）在钩子返回时自动回退。这样 libc 内部对 `dst` 的嵌套调用
（`stat→fstatat`、`realpath→lstat`、别名路径等）在本次操作内一并跳过隐藏判定，而**后续直接
访问 `dst` 仍照常隐藏**。

扩展属性族钩子同样先重定向再判隐藏，因此 `security.selinux` 等标签随重定向变为 `dst` 的标签。

## 5. `/proc` 脱敏

`handle_proc_file()` 在 `open` 阶段拦截，按 `proc_kind()` 分类：

- `environ`：按 `cfg_vars` 表逐条过滤配置变量（`LD_PRELOAD` 仅精确匹配目标值）；
- `maps/smaps/smaps_rollup`：按行过滤含 `HIDE_SO` 匹配项的行；
- `mounts/mountinfo/mountstat[s]`：按行过滤挂载点匹配的行。

实现为**流式过滤**：边读边写匿名内存文件（`memfd_create`），经 64 KiB 聚合缓冲（`obuf`）减少
小写入系统调用，只保留一个不完整尾段，避免整文件双缓冲。单条超过 `PROC_MAX_SEG`（8 MiB）、
读取/分配/写入失败一律**失败关闭**（返回 `-1`，绝不返回原始内容）。

`map_files` 为目录，改由 `readdir/readlink/open/stat` 层读取符号链接目标并按 `HIDE_SO` 过滤；
先用 `maybe_map_files()` 做廉价判断（仅 `/proc/.../map_files/`）。

## 6. 环境变量自隐藏

构造函数：

1. `raw_getenv()` **直接扫描 `environ`** 读取配置（不经 `dlsym(getenv)`、不依赖 libc，必然可见）；
2. 每个配置经 `load_cfg()` 解析，把已设置的变量从 `environ` **原地移位删除**（非 `unsetenv`；
   bionic 下 `main` 的 envp 与 `environ` 同块内存）；
3. 保存 `NAME=value` 到 `inject_entries[]` 供 execve 回注；配置变量名/长度集中在 `cfg_vars[]`，
   解析、脱敏、getenv、回注全部复用同一张表。

运行期：

- `getenv`/`secure_getenv` 对配置变量返回 `NULL`（`LD_PRELOAD` 仅当等于目标时）；
- `/proc/<pid>/environ` 读取时脱敏；
- `execve` 见 §7。

## 7. execve 策略

路径处理：

1. `ALLOW_ACCESS` 优先：字面路径命中 → 走原路径，不重定向、不隐藏；
2. 否则按 `REDIRECT_FILES` 改写；命中重定向则本次跳过隐藏判定；
3. 未命中重定向且 `HIDE_FILES` 命中 → `ENOENT`（隐藏文件不可执行）。

环境处理（选择一种重写模式后由 `env_rebuild()` 生成 ops 表）：

1. `SKIP_RESTRICTED_PATHS` 命中目标 → `ENV_STRIP_ALL`，全剥离；
2. 用户运行期改过 `LD_PRELOAD`（或 envp 中的值不等于目标）→ `ENV_KEEP_LD`，保留之、剥其余；
3. 静态链接目标（无 `PT_INTERP`，含脚本 shebang 解析）或本进程非经 `LD_PRELOAD` 加载
   → `ENV_STRIP_ALL`，只剥离；
4. 其余动态目标 → `ENV_REINJECT`，剥掉后按需回注全部配置，保证子进程加载 `hide.so` 且配置一致。

静态判定：一次读入 ELF 头，查找 `PT_INTERP`；脚本则递归判断其 shebang 解释器。环境重建内存
分配失败时**失败关闭**（`ENOMEM`），绝不把未脱敏配置交给子进程。

## 8. 并发

- `next()` 用互斥锁串行化 `dlsym`，消除懒加载竞争；`GET_REAL` 由宏统一生成懒加载代码。
- 目录映射表用互斥锁保护；线程内用 TLS 缓存最近目录、干净目录、重入标志。
- 重定向作用域（目标路径/身份/深度）全部为 TLS，天然线程独立。
- 配置数据在构造函数后只读。

## 9. 性能

- 无配置时各钩子走零成本快速路径；
- `HIDE_FILES` 路径条目按长度排序，字符串匹配可提前退出；祖先回溯零分配（仅存前缀长度），
  只有确认整支干净后才写缓存；
- 路径条目的 inode 身份集中在独立数组，`ino_exact` 只在有身份条目上遍历；
- 目录列举用 `d_ino` 与干净目录缓存避免逐项 `stat`；
- `/proc` 过滤为流式 + 64 KiB 聚合写，内存占用与行长相关。

## 10. 边界与权衡

- `syscall()` 直接调用绕过全部钩子（`LD_PRELOAD` 固有边界）；
- `/proc/<pid>/{mem,pagemap}` 为二进制，无法路径隐藏；
- 钩子非 async-signal-safe；
- `HIDE_FILES`/`ALLOW_ACCESS` 仅接受绝对路径，非绝对条目告警忽略；
- 关键常量：`MAXHIDE=64`、`MAXALLOW=64`、`MAXREDIR=32`、`MAXRPRE=32`、`MAXTOK=64`、
  `MAXDIRS=256`（满则 FIFO 淘汰）、`DCACHE=128`、`PROC_MAX_SEG=8 MiB`、`PATH_MAX` 缓冲、
  祖先回溯深度上限 128。
