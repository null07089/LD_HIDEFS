# 设计文档（Design）

[← 返回 README](../README.md) · [使用文档](USAGE.md) · [English usage](USAGE.en.md)

本文说明 `hide.so` 的内部实现：钩子机制、匹配算法、`/proc` 脱敏、环境自隐藏、性能与并发。

---

## 1. 总体结构

单文件 `hide.c`，编译为动态库。核心组件：

```
init_hidden()                 构造函数：解析配置、环境自隐藏、LD_PRELOAD 自隐藏
path_hidden / abs_hidden      隐藏匹配（裸名 / 路径 / 祖先 inode）
redirect_into                 重定向匹配（bind 风格）
handle_proc_file              /proc 文本脱敏（流式 → memfd）
build_env                     execve 环境重写（剥离/回注）
GET_REAL / next               RTLD_NEXT 懒加载
```

所有对外函数以 `LD_PRELOAD` 方式**插桩** libc 包装函数；真实实现由 `dlsym(RTLD_NEXT, ...)`
取得。

## 2. 钩子清单

- 属性：`stat/stat64/lstat/lstat64/fstatat/fstatat64/statx/access/faccessat`
- 打开：`open/open64/openat/openat64/__open_2/__openat_2/creat/creat64/fopen/fopen64/freopen/freopen64/opendir/fdopendir/closedir`
- 目录：`readdir/readdir64/scandir`
- 链接：`readlink/readlinkat/__readlinkat_chk/symlink/symlinkat/link/linkat`
- 保护写：`unlink/unlinkat/remove/rmdir/rename/renameat/renameat2/chmod/fchmodat/chown/lchown/utimes/utime/utimensat/truncate/truncate64/mkdir/mkdirat`
- 文件系统信息：`statfs/statfs64/statvfs/statvfs64`
- 进程：`execve`
- 环境：`getenv/secure_getenv/setenv/unsetenv/putenv/clearenv`

> 约定：所有路径类钩子按 `REDIR`（重定向）→ `path_hidden`/`map_files_entry_hidden`（隐藏）
> → 真实调用的顺序处理（`execve` 例外，见 §7）。

## 3. 隐藏匹配（HIDE_FILES）

初始化时把条目分为两类：

- **裸名**：`strcmp` 匹配任意路径分量；
- **路径条目**：`normalize()` 规范化（存在则 `realpath`，否则词法绝对化），并记录
  `st_dev/st_ino/is_dir`。

运行期 `path_hidden()`：

1. 裸名分量扫描（零分配、零系统调用）；
2. 词法绝对化（`lex_abs`，仅相对路径需要一次 `getcwd`）；
3. 字符串精确/前缀匹配；
4. 一次直连 `fstatat` 做 inode 身份匹配（跨绑定挂载别名）；
5. 目录条目逐级向上比较父目录 inode，并用**线程内“干净目录”缓存**提前终止。

`readdir/scandir` 使用 `dirent.d_ino` 做快速过滤，绝大多数条目无需 `stat`。

## 4. 重定向（REDIRECT_FILES）

`redirect_into()` 把路径与规则 `src` 比较：

- 文件：精确相等 → 命中；
- 目录：`src` + `/` 前缀 → 用 `dst` + 余部替换。

命中结果写入**调用方栈上 `alloca` 缓冲**（`REDIR` 宏），每次调用独立分配，因此：

- 同一函数内多次改写（如 `rename(old,new)`）互不覆盖；
- 被调用方内部再进入钩子（如 `realpath` 内部 `lstat`）也不会破坏正在使用的路径。

第一条命中的规则生效，不链式。

## 5. `/proc` 脱敏

`handle_proc_file()` 在 `open` 阶段拦截，按 `proc_kind()` 分类：

- `environ`：按 NUL 逐条过滤配置变量；
- `maps/smaps/smaps_rollup`：按行过滤含 `HIDE_SO` 匹配项的行；
- `mounts/mountinfo/mountstat[s]`：按行过滤挂载点匹配的行。

实现为**流式过滤**：边读边写匿名内存文件（`memfd_create`），只保留一个不完整尾段，
避免整文件双缓冲。无法创建 memfd 时**失败关闭**（绝不返回原始内容）。

`map_files` 为目录，改由 `readdir/readlink/open/stat` 层读取符号链接目标并按 `HIDE_SO` 过滤。

## 6. 环境变量自隐藏

构造函数：

1. 用 `dlsym(RTLD_NEXT, "getenv")` 读取配置（绕过本库 `getenv` 钩子）；
2. 把已设置的配置变量从 `environ` **原地移位删除**（非 `unsetenv`；bionic 下 `main` 的 envp
   与 `environ` 同块内存）；
3. 保存 `NAME=value` 供 execve 回注。

运行期：

- `getenv`/`secure_getenv` 对配置变量返回 `NULL`（`LD_PRELOAD` 仅当等于目标时）；
- `/proc/<pid>/environ` 读取时脱敏；
- `execve` 见 §7。

## 7. execve 策略

- **不隐藏、不重定向**：执行字面路径（因此能执行被隐藏的原文件）。
- 环境处理分支：
  1. 受限 namespace 目标 → 剥离全部配置；
  2. 用户运行期改过 `LD_PRELOAD`（或 envp 中的值不等于目标）→ 只剥离、不接管 `LD_PRELOAD`；
  3. 静态链接目标（无 `PT_INTERP`，含脚本 shebang 解析）或本进程非经 `LD_PRELOAD` 加载
     → 只剥离；
  4. 其余动态目标 → 剥掉后按需**回注**配置，保证子进程加载 `hide.so` 且配置一致。

静态判定：直接读 ELF 程序头，查找 `PT_INTERP`；脚本则递归判断其 shebang 解释器。

## 8. 并发

- `next()` 用互斥锁串行化 `dlsym`，消除懒加载竞争；
- 目录映射表用互斥锁保护；线程内用 TLS 缓存最近目录、干净目录、重入标志；
- 配置数据在构造函数后只读。

## 9. 性能

- 无配置时各钩子走零成本快速路径；
- 纯裸名配置几乎与不加载 `hide.so` 相当；
- 路径条目最多一次 `fstatat`；目录列举用 `d_ino` 与干净目录缓存避免逐项 `stat`；
- `/proc` 过滤为流式，内存占用与行长相关。

## 10. 边界与权衡

- `syscall()` 直接调用绕过全部钩子（`LD_PRELOAD` 固有边界）；
- `/proc/<pid>/{mem,pagemap}` 为二进制，无法路径隐藏；
- 钩子非 async-signal-safe；
- 关键常量：`MAXHIDE=64`、`MAXREDIR=32`、`MAXRPRE=32`、`MAXTOK=64`、`MAXDIRS=256`、
  `PATH_MAX` 缓冲、回溯深度上限 128。
