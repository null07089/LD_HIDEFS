# hide.so 使用文档

[← 返回 README](../README.md) · [设计文档](DESIGN.md) · [GPL-3.0 许可证](../LICENSE) · [English](USAGE.en.md)

一个基于 `LD_PRELOAD` 的 Android/bionic 用户态“文件隐身 + 重定向 + /proc 脱敏”动态库。
所有配置**仅来自运行时环境变量**，没有编译期默认；被设置的配置变量本身也会被彻底隐藏。

> ⚠️ **免责声明**：本技术为双用途，请仅在**你拥有或获授权测试**的设备上使用；不得用于规避安全
> 控制、隐藏恶意程序或违反法律。需要 root/`LD_PRELOAD` 支持，**后果自负**，不提供任何担保。

---

## 1. 文件与构建

仓库/目录内文件：

| 文件 | 说明 |
|---|---|
| `hide.c` | 全部源码 |
| `hide.so` | 已编译产物 |
| `test_hide.sh` | 一键自测脚本（构建 + 27 项用例）|
| `docs/USAGE.md` | 本文档 |

构建：

```sh
clang -shared -fPIC -Wall -Wextra -O2 -o hide.so hide.c
```

加载（必须让**执行 `execve` 的进程自身**加载了本库，钩子才生效）：

```sh
# 方式一：当前命令临时加载
LD_PRELOAD=/abs/path/hide.so <command>

# 方式二：整个会话加载（推荐）
LD_PRELOAD=/abs/path/hide.so bash
# 或
export LD_PRELOAD=/abs/path/hide.so
```

> 注意：`LD_PRELOAD` 的值即“需要精确隐藏的目标”，本库会自动读取（无需另外配置），
> 并将其对应的动态库从 `/proc/<pid>/maps` 等中隐藏。

---

## 2. 配置变量总览

| 环境变量 | 作用 | 分隔/格式 | 未设置时 |
|---|---|---|---|
| `HIDE_FILES` | 隐藏文件/目录（**仅绝对路径**） | `/a/b:/c/d` | 不隐藏任何东西 |
| `ALLOW_ACCESS` | 放行名单：豁免 fstatat/faccessat/execve 的隐藏判定 | `/a/b:/c/d` | 无豁免 |
| `REDIRECT_FILES` | 用户态 bind 重定向（含 `execve` 与扩展属性） | `src=dst[:...]` | 不重定向 |
| `HIDE_SO` | 在 maps/smaps/map_files 中隐藏库 | `lib.so:/path/lib.so` | 仅自动隐藏 `LD_PRELOAD` 自身 |
| `HIDE_MOUNT` | 隐藏挂载点 | `/data:/mnt/secret` | 不隐藏挂载 |
| `SKIP_RESTRICTED_PATHS` | 跳过注入的路径前缀（受限 linker namespace） | `/vendor:/odm:...` | 不跳过 |

以上 6 个变量一旦设置都会被**彻底隐藏**（详见 §8）。

> v1.0 的 `HIDE_RESTRICTED_PATHS` 已更名为 `SKIP_RESTRICTED_PATHS`；旧名不再解析、也不隐藏。

---

## 3. HIDE_FILES —— 隐藏文件/目录

格式：冒号分隔的**绝对路径**列表。**只支持绝对路径**：
非绝对路径条目会被忽略并在 stderr 打印告警（请自行展开为绝对路径）。

匹配规则：

- 路径**精确命中**，或以 `/` 为边界的**目录前缀命中**（目录命中则整棵子树隐藏）；
- 初始化时做 `realpath` 规范化；运行期先字符串匹配，再用 **inode 身份**（`st_dev`+`st_ino`）
  匹配，可跨绑定挂载别名（如 `/data/data` ↔ `/data/user/0`）和符号链接；
- 目录条目会向上回溯父目录 inode，命中即视为“目录内”；
- 被隐藏后，`stat/lstat/access/open/opendir/readlink/rename/unlink/chmod/xattr/...` 一律返回
  `ENOENT`；目录列举（`readdir/readdir64/scandir`）中也会被过滤掉；
- **`execve` 也受隐藏判定**：命中 `HIDE_FILES` 且不在 `ALLOW_ACCESS` 中的文件不允许执行
  （返回 `ENOENT`）。这是相对 v1.0 的行为变化（旧版隐藏文件仍可被 exec）。

示例：

```sh
# 隐藏 /data/tmp 与 /data/local/secret（含其后代）
LD_PRELOAD=./hide.so HIDE_FILES="/data/tmp:/data/local/secret" bash

# 指定文件消失
LD_PRELOAD=./hide.so HIDE_FILES=/tmp/secret bash -c 'ls /tmp; cat /tmp/secret'
```

> 裸名（`name`）与相对路径（`./name`）在当前版本已不再支持；请改写为绝对路径。

---

## 4. ALLOW_ACCESS —— 放行名单

格式：冒号分隔的**绝对路径**列表；目录条目对整棵子树生效（命中精确路径，或以 `/` 为边界的
子路径）。非绝对路径条目被忽略并告警。

作用范围**只有两个**：

1. `fstatat`/`fstatat64`/`faccessat` 探测：
   - 本次操作命中重定向时跳过隐藏（目标即便在 `HIDE_FILES` 中也可达）；
   - 否则对字面路径判定，命中名单才豁免 `HIDE_FILES`；
2. `execve`：字面路径命中名单时，**走原路径直接执行**，既不重定向也不隐藏。

其余钩子（`stat`/`lstat`/`statx`/`access`/`open`/`readlink`/…）**不受** `ALLOW_ACCESS` 影响，
隐藏名单照常生效。

> bionic 无 `newfstatat` 符号，其语义即 `fstatat`/`fstatat64`。

示例：

```sh
# secret 整体隐藏，但 secret/keep 允许被探测与执行
LD_PRELOAD=./hide.so HIDE_FILES=/data/local/secret \
  ALLOW_ACCESS=/data/local/secret/keep bash
```

---

## 5. REDIRECT_FILES —— 用户态 bind 重定向

格式：`src=dst`，冒号分隔多条；首个 `=` 分割。相对路径按 `dirfd` 语义解析（`/proc/self/fd`）。

- `src` 是**文件** → 精确替换为 `dst`；
- `src` 是**目录** → 前缀替换（`src/xxx` → `dst/xxx`）；
- 第一条命中的规则生效，不链式。

重定向对读写/属性/扩展属性等操作透明生效：`stat/open/access/opendir/readlink/unlink/rename/
chmod/utimes/truncate/creat/fopen/statfs/getxattr/setxattr/listxattr/...`。
**`execve` 同样参与重定向**：命中 `src` 时路径会被改写为 `dst` 再执行。

优先级：**本次操作命中重定向时跳过 `HIDE_FILES` 判定**——即便 `dst` 本身在隐藏名单中，
经 `src` 访问仍可达（视为“`dst` 是本次重定向的目标”）；直接访问 `dst`（未重定向）仍照常隐藏。

扩展属性同样改写，因此 SELinux 标签（`security.selinux`）随重定向变为 `dst` 的标签。

示例：

```sh
# 读 /etc/motd 实际读 /data/motd.fake
LD_PRELOAD=./hide.so REDIRECT_FILES="/etc/motd=/data/motd.fake" cat /etc/motd

# 目录整体重定向
LD_PRELOAD=./hide.so REDIRECT_FILES="/sdcard/secure=/data/local/secure" ls /sdcard/secure

# 目标本身被隐藏，经 src 仍可达；直接访问 dst 仍隐藏
LD_PRELOAD=./hide.so HIDE_FILES=/data/real \
  REDIRECT_FILES="/data/alias=/data/real" cat /data/alias
```

---

## 6. HIDE_SO —— 隐藏动态库路径

作用对象：

- `/proc/<pid>/maps`、`/proc/<pid>/smaps`、`/proc/<pid>/smaps_rollup`（文本行过滤）
- `/proc/<pid>/map_files`（目录项的符号链接目标过滤，含按地址 `open/stat/readlink`）

格式：`:` 分隔的匹配项。

- 含 `/` 的条目会先 **`realpath` 绝对化**，以匹配 maps 中显示的绝对路径；
- 裸名按路径分量边界匹配；
- **无需配置也会自动把 `LD_PRELOAD` 自身**（其值 realpath 后）加入，从而固定隐藏 `hide.so`。

示例：

```sh
# 额外隐藏某个库
LD_PRELOAD=./hide.so HIDE_SO="libtarget.so:/tmp/other.so" bash
# maps/smaps/map_files 中这些路径消失
```

匹配边界：命中必须是“路径分量/前缀”，左边界为串首、`/` 或空白，右边界为串尾、`/` 或空白
（空白容错用于 maps 中的 “ (deleted)” 后缀）。因此 `libc.so` 只隐藏真正叫 `libc.so` 的分量，
而不会因 `libc` 而误伤。

---

## 7. HIDE_MOUNT —— 隐藏挂载信息

作用对象：

- `/proc/<pid>/mounts`、`/proc/<pid>/mountinfo`、`/proc/<pid>/mountstat`、`/proc/<pid>/mountstats`
  （同时支持无 pid 形式 `/proc/mounts` 等）
- `statfs`/`statfs64`/`statvfs`/`statvfs64`：被隐藏挂载点返回 `ENOENT`
- `umount`/`umount2`：被隐藏挂载点返回 `EINVAL`（直接 `syscall(SYS_umount2,...)` 无法拦截）

格式：`:` 分隔路径；匹配挂载点**精确**或**前缀**（`/a` 命中 `/a` 及 `/a/...`）。

> 注意：不影响目录列举——`readdir/scandir` 仍会列出该挂载点。

示例：

```sh
LD_PRELOAD=./hide.so HIDE_MOUNT="/data:/mnt/secret" bash
cat /proc/self/mounts   # /data 等条目消失
stat -f /data           # 失败（ENOENT）
umount /data            # 失败（EINVAL）
```

---

## 8. 环境变量自隐藏机制

所有已设置的配置变量（`HIDE_FILES`、`ALLOW_ACCESS`、`REDIRECT_FILES`、`SKIP_RESTRICTED_PATHS`、
`HIDE_SO`、`HIDE_MOUNT`，以及等于目标的 `LD_PRELOAD`）都会：

1. **构造期从自身 `environ` 数组原地删除**（移位 + 置 NULL，非 `unsetenv`）：
   `echo $VAR`、`env`、`printenv`、`env | grep` 均看不到；
2. `getenv()` / `secure_getenv()` 返回 `NULL`；
3. `/proc/<pid>/environ` 读取时脱敏（memfd 返回过滤后的内容）；
4. **动态子进程 execve 时回注**，使子进程仍加载 hide.so 且继承配置；
5. **静态链接目标 / `SKIP_RESTRICTED_PATHS` 命中目标剥离**，不回注，避免泄露。

> 注意：子进程“先回注、再在其构造函数里原地删除”，逐层递归，稳定。
> 构造期直接扫描 `environ` 读取配置，不依赖 `dlsym(getenv)`，因此不会漏删泄露。

---

## 9. SKIP_RESTRICTED_PATHS —— 受限 linker namespace

Android 上 `/vendor`、`/odm`、`/product`、`/system_ext`、`/apex` 等分区的可执行文件运行在受限
linker namespace，其 `permitted_paths` 不允许从 `/data` 注入 `LD_PRELOAD`，否则会报：

```
WARNING: linker: library ... is not accessible for the namespace ...
CANNOT LINK EXECUTABLE ...: library ... is not accessible for the namespace
```

因此这些目标必须剥离注入。用该变量列出前缀（v1.0 中名为 `HIDE_RESTRICTED_PATHS`）：

```sh
LD_PRELOAD=./hide.so SKIP_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" bash
```

命中（前缀边界匹配）时：剥离 `LD_PRELOAD` 与全部配置、不注入，与静态目标同样处理。
未设置则不限制——在 Android 上强烈建议设置上面的值。

> 匹配基于词法绝对化后的字面路径，不再对符号链接做 `realpath` 兜底；
> 若可执行文件是符号链接且真实目标位于受限前缀，请把链接所在前缀也一并列出。

---

## 10. execve 行为小结

- **受隐藏**：命中 `HIDE_FILES` 且不在 `ALLOW_ACCESS` 中的文件不允许执行（`ENOENT`）。
- **参与重定向**：先按 `REDIRECT_FILES` 改写路径；命中重定向时本次跳过隐藏判定。
- `ALLOW_ACCESS` 优先：字面路径命中名单时走原路径，不重定向也不隐藏。
- 会做环境处理：
  - 目标为**静态链接**（无 `PT_INTERP`，含脚本 shebang 解析）→ 剥离全部配置；
  - 目标为 **`SKIP_RESTRICTED_PATHS` 命中** → 剥离全部配置；
  - 目标为**动态且能保证加载 hide.so**（本进程经 `LD_PRELOAD` 加载，回注有效）→ 回注配置；
  - 本进程若非经 `LD_PRELOAD` 加载（无从保证子进程加载 hide.so）→ 只剥离不回注，避免泄露。
- 环境重写内存分配失败时**失败关闭**（返回 `ENOMEM`），绝不把未脱敏配置传给子进程。
- 运行期若程序自行修改 `LD_PRELOAD`（`setenv`/`putenv`/`unsetenv`/`clearenv`，或直接改了 envp，
  如 bash `export`）且新值不等于当前目标 → **停止接管** `LD_PRELOAD`（不再剥离/回注），尊重用户设置。

---

## 11. 组合示例

```sh
LD_PRELOAD=/data/local/hide.so \
HIDE_FILES="/data/tmp:/data/local/secret" \
ALLOW_ACCESS="/data/local/secret/keep" \
REDIRECT_FILES="/etc/motd=/data/local/motd.fake" \
HIDE_SO="libtarget.so" \
HIDE_MOUNT="/data/local/secure" \
SKIP_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" \
bash
```

---

## 12. 工作原理

- 钩子通过 `dlsym(RTLD_NEXT, ...)` 取得真实函数；用 `GET_REAL` 宏统一懒加载（加锁串行化），
  缺失符号时降级为 `ENOSYS` 而非退出。
- 路径匹配优先“零系统调用”的词法规范化（含无 `.`/`..` 的绝对路径快路径）；路径条目的 inode
  身份用直连 `fstatat` 系统调用获取，并按长度排序以提前退出匹配。
- 重定向改写路径到**栈上 alloca 缓冲**（每次调用独立，避免多路径/重入互相覆盖）；命中目标用
  TLS 记录，嵌套钩子（如 `stat→fstatat`、`realpath→lstat`）在本次操作内一并豁免隐藏。
- `/proc` 文本脱敏采用**流式过滤**：边读边写 `memfd`，64 KiB 聚合写出，只保留一个不完整尾段；
  单条超过 8 MiB 或写入失败则**失败关闭**（绝不返回原始内容）。
- `map_files` 通过 `readlinkat` 目标匹配 HIDE_SO。
- 为规避 libc 内部递归，`stat` 族用直连系统调用；`realpath` 仅在确有需要时解析。
- 大量钩子由 `W_*` 宏生成（路径/双路径/at 变体），统一执行“重定向 → 隐藏判定 → 真实调用”。

性能：无配置时各钩子走零成本快速路径；路径条目按长度排序、祖先回溯零分配；目录列举使用
`d_ino` 快速过滤与线程内“干净目录”缓存，避免逐项 `stat`；目录映射满时按 FIFO 淘汰，保证最近
打开的目录仍可跟踪。

---

## 13. 已知限制

1. **`HIDE_FILES` 仅支持绝对路径**；裸名/相对路径被忽略并告警。相对路径需调用方自行展开。
2. **`syscall()` 直接调用绕过所有钩子**（如部分 gnulib/coreutils 用原始 `renameat2`、`getdents64`）。
   这是 `LD_PRELOAD` 的固有边界。bionic 未导出 `getdents/getdents64`，无法钩。
3. `/proc/<pid>/mem`、`/proc/<pid>/pagemap` 是二进制、不含路径，无法做路径隐藏。
4. 钩子非 `async-signal-safe`（含 `malloc`/锁），**信号处理器内**调用有死锁/崩溃风险。
5. 运行期程序自行 `setenv/putenv` 的 `HIDE_*` 变量未被跟踪（仅跟踪 `LD_PRELOAD`）；`env` 可能短暂可见，
   但 `getenv` 与 execve 仍会处理。
6. “干净目录”缓存、路径条目 inode 身份与 `ALLOW_ACCESS` 词法展开在初始化时确定；运行期挂载/
   符号链接变化可能导致判定过期。
7. `MAXHIDE=64`、`MAXALLOW=64`、`MAXREDIR=32`、`MAXRPRE=32`、`MAXTOK=64`、`MAXDIRS=256`
   为编译期上限，超出静默丢弃（目录映射满时 FIFO 淘汰）。
8. `HIDE_MOUNT` 不影响 `readdir/scandir` 的目录列举，仅过滤 `/proc` 挂载信息与 statfs/umount。
9. `env -i` 等自定义 envp 会被强制回注配置（隐藏无法绕过，属设计取舍）。

---

## 14. 自测

```sh
bash test_hide.sh
```

覆盖：配置隐藏、绝对路径隐藏、相对条目忽略、`ALLOW_ACCESS`（fstatat/faccessat/execve）、
重定向（含隐藏目标可达、`execve` 重定向、双路径回归）、`HIDE_SO`（maps/smaps/自动隐藏）、
`/proc/mounts`、`statfs`、`SKIP_RESTRICTED_PATHS` 等，共 27 项。

---

## 15. 常见问题（FAQ）

**Q：为什么 `ls` 看不到隐藏文件，但 `mv` 还能操作它？**
A：`HIDE_FILES` 通过钩子过滤，但某些程序用原始系统调用（绕过 libc 包装）会穿透；日常工具（ls/cat/rm 等）正常。

**Q：为什么我写了 `HIDE_FILES=secret` 却没有任何效果？**
A：当前版本起 `HIDE_FILES` 只接受绝对路径；裸名/相对路径会被忽略并向 stderr 告警。请写完整绝对路径。

**Q：为什么隐藏 `/system/bin/sh` 后有些命令报 `Permission denied` / 回退到 `/vendor/bin/sh`？**
A：shell 的命令解析会用 `stat/access` 扫 PATH，隐藏使 `/system/bin/sh` 被跳过，于是回退到 PATH 里
其它 `sh`（如 `/vendor/bin/sh`），而 vendor 程序运行在受限 namespace。建议**不要隐藏 `/system/bin/sh`**，
需要替换行为时在 PATH 更靠前放一个**可见的** wrapper。

**Q：`execve` 会执行被隐藏/被重定向的文件吗？**
A：隐藏文件默认**不可执行**（`ENOENT`），除非在 `ALLOW_ACCESS` 中；重定向对 `execve` 生效，
命中 `src` 时会执行 `dst`。

**Q：如何只隐藏 `hide.so` 自身？**
A：不用配置。加载后会自动把 `LD_PRELOAD` 值 realpath 后加入 `HIDE_SO`，从 maps/smaps/map_files 中隐藏。

**Q：为什么设置的环境变量 `echo $HIDE_FILES` 是空的？**
A：这是设计：所有配置变量在构造期从自身环境原地删除，`env/getenv/printenv/echo` 都看不到。

**Q：旧的 `HIDE_RESTRICTED_PATHS` 还能用吗？**
A：不能。旧名已更名为 `SKIP_RESTRICTED_PATHS`，旧名不再解析，也不会被隐藏——请改用新名。
