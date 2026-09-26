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
| `test_hide.sh` | 一键自测脚本（构建 + 16 项用例）|
| `使用文档.md` | 本文档 |

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
| `HIDE_FILES` | 隐藏文件/目录 | `name:./rel:/abs` | 不隐藏任何东西 |
| `REDIRECT_FILES` | 用户态 bind 重定向 | `src=dst[:...]` | 不重定向 |
| `HIDE_SO` | 在 maps/smaps/map_files 中隐藏库 | `lib.so:/path/lib.so` | 仅自动隐藏 `LD_PRELOAD` 自身 |
| `HIDE_MOUNT` | 隐藏挂载点 | `/data:/mnt/secret` | 不隐藏挂载 |
| `HIDE_RESTRICTED_PATHS` | 受限 linker namespace 前缀 | `/vendor:/odm:...` | 不限制（Android 上建议设置）|

以上 5 个变量一旦设置都会被**彻底隐藏**（详见 §7）。

---

## 3. HIDE_FILES —— 隐藏文件/目录

格式：冒号分隔，每个条目三种写法：

| 写法 | 含义 |
|---|---|
| `name` | **裸名**：任意路径中命中该名字即隐藏（全局）|
| `./name` | **相对路径**：只隐藏“本库初始化时进程 cwd 下”的该条目 |
| `/a/b/name` | **绝对路径**：只隐藏这一条路径；若它是目录，则其**所有后代**也隐藏 |

匹配要点：

- 裸名按“路径分量全等”匹配（`namex` 不会命中 `name`）。
- 路径条目在初始化时做 `realpath` 规范化；实际判断时：
  - 先字符串精确/前缀匹配；
  - 再用 **inode 身份**（`st_dev`+`st_ino`）匹配，可跨绑定挂载别名（如 `/data/data` ↔ `/data/user/0`）和符号链接；
  - 目录条目会向上回溯父目录 inode，命中即视为“目录内”。
- 被隐藏后，`stat/lstat/access/open/opendir/readlink/rename/unlink/chmod/...` 一律返回 `ENOENT`；
  目录列举（`readdir/readdir64/scandir`）中也会被过滤掉。

示例：

```sh
LD_PRELOAD=./hide.so HIDE_FILES="secret:./local:/data/system/sh_raw" bash
```

控制示例（指定文件消失）：

```sh
LD_PRELOAD=./hide.so HIDE_FILES=/tmp/secret bash -c 'ls /tmp; cat /tmp/secret'
```

---

## 4. REDIRECT_FILES —— 用户态 bind 重定向

格式：`src=dst`，冒号分隔多条；首个 `=` 分割。

- `src` 是**文件** → 精确替换为 `dst`；
- `src` 是**目录** → 前缀替换（`src/xxx` → `dst/xxx`）。

重定向对读写类操作透明生效：`stat/open/access/opendir/readlink/unlink/rename/chmod/utimes/truncate/creat/fopen/statfs/...`。

示例：

```sh
# 读 /etc/motd 实际读 /data/motd.fake
LD_PRELOAD=./hide.so REDIRECT_FILES="/etc/motd=/data/motd.fake" cat /etc/motd

# 目录整体重定向
LD_PRELOAD=./hide.so REDIRECT_FILES="/sdcard/secure=/data/local/secure" ls /sdcard/secure
```

### 重要例外：`execve` 不参与重定向

- `execve` 始终执行**字面路径**，因此也能执行被 `HIDE_FILES` 隐藏的原文件。
- 因此“把 `/system/bin/sh` 重定向到自己的 wrapper”这类需求**不通过重定向实现**；
  可靠做法是在 PATH 更靠前的位置放一个**可见的** wrapper，或直接调用绝对路径。
- 规则 `a=b` 只把“读 a”变成“读 b”，不会反向影响执行 b。

---

## 5. HIDE_SO —— 隐藏动态库路径

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
LD_PRELOAD=./hide.so HIDE_SO="libtarget.so:/data/system/other.so" bash
# maps/smaps/map_files 中这些路径消失
```

匹配边界：命中必须是“路径分量/前缀”，左边界为串首、`/` 或空白，右边界为串尾、`/` 或空白
（空白容错用于 maps 中的 “ (deleted)” 后缀）。因此 `libc.so` 只隐藏真正叫 `libc.so` 的分量，
而不会因 `libc` 而误伤。

---

## 6. HIDE_MOUNT —— 隐藏挂载信息

作用对象：

- `/proc/<pid>/mounts`、`/proc/<pid>/mountinfo`、`/proc/<pid>/mountstat`、`/proc/<pid>/mountstats`
  （同时支持无 pid 形式 `/proc/mounts` 等）
- `statfs`/`statfs64`/`statvfs`/`statvfs64`：被隐藏挂载点返回 `ENOENT`

格式：`:` 分隔路径；匹配挂载点**精确**或**前缀**（`/a` 命中 `/a` 及 `/a/...`）。

示例：

```sh
LD_PRELOAD=./hide.so HIDE_MOUNT="/data:/mnt/secret" bash
cat /proc/self/mounts   # /data 等条目消失
stat -f /data           # 失败（ENOENT）
```

---

## 7. 环境变量自隐藏机制

所有已设置的配置变量（`HIDE_FILES`、`REDIRECT_FILES`、`HIDE_RESTRICTED_PATHS`、`HIDE_SO`、`HIDE_MOUNT`、
以及等于目标的 `LD_PRELOAD`）都会：

1. **构造期从自身 `environ` 数组原地删除**（移位 + 置 NULL，非 `unsetenv`）：
   `echo $VAR`、`env`、`printenv`、`env | grep` 均看不到；
2. `getenv()` / `secure_getenv()` 返回 `NULL`；
3. `/proc/<pid>/environ` 读取时脱敏（memfd 返回过滤后的内容）；
4. **动态子进程 execve 时回注**，使子进程仍加载 hide.so 且继承配置；
5. **静态链接目标 / 受限 namespace 目标剥离**，不回注，避免泄露。

> 注意：子进程“先回注、再在其构造函数里原地删除”，逐层递归，稳定。

---

## 8. HIDE_RESTRICTED_PATHS —— 受限 linker namespace

Android 上 `/vendor`、`/odm`、`/product`、`/system_ext`、`/apex` 等分区的可执行文件运行在受限
linker namespace，其 `permitted_paths` 不允许从 `/data` 注入 `LD_PRELOAD`，否则会报：

```
WARNING: linker: library ... is not accessible for the namespace ...
CANNOT LINK EXECUTABLE ...: library ... is not accessible for the namespace
```

因此这些目标必须剥离注入。用该变量列出前缀：

```sh
LD_PRELOAD=./hide.so HIDE_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" bash
```

命中（前缀边界匹配）时：剥离 `LD_PRELOAD` 与全部配置、不注入。
未设置则不限制——在 Android 上强烈建议设置上面的值。

---

## 9. execve 行为小结

- **不隐藏**：可执行被 `HIDE_FILES` 隐藏的文件（隐藏只影响读写及目录列举）。
- **不重定向**：执行字面路径。
- 会做环境处理：
  - 目标为**静态链接**（无 `PT_INTERP`，含脚本 shebang 解析）→ 剥离全部配置；
  - 目标为**受限 namespace** → 剥离全部配置；
  - 目标为**动态且能保证加载 hide.so**（本进程经 `LD_PRELOAD` 加载，回注有效）→ 回注配置；
  - 本进程若非经 `LD_PRELOAD` 加载（无从保证子进程加载 hide.so）→ 只剥离不回注，避免泄露。
- 运行期若程序自行修改 `LD_PRELOAD`（`setenv`/`putenv`/`unsetenv`/`clearenv`，或直接改了 envp，
  如 bash `export`）且新值不等于当前目标 → **停止接管** `LD_PRELOAD`（不再剥离/回注），尊重用户设置。

---

## 10. 组合示例

```sh
LD_PRELOAD=/data/local/hide.so \
HIDE_FILES="/data/system/sh_raw:/data/local/secret" \
REDIRECT_FILES="/etc/motd=/data/local/motd.fake" \
HIDE_SO="libtarget.so" \
HIDE_MOUNT="/data/local/secure" \
HIDE_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" \
bash
```

---

## 11. 工作原理

- 钩子通过 `dlsym(RTLD_NEXT, ...)` 取得真实函数；用 `GET_REAL` 宏统一懒加载（加锁串行化）。
- 路径匹配优先“零系统调用”的词法规范化；路径条目的 inode 身份用直连 `fstatat` 系统调用获取。
- 重定向改写路径到**栈上 alloca 缓冲**（每次调用独立，避免多路径/重入互相覆盖）。
- `/proc` 文本脱敏采用**流式过滤**：边读边写 `memfd`，只保留一个不完整尾段；失败关闭（绝不返回原始内容）。
- `map_files` 通过 `readlinkat` 目标匹配 HIDE_SO。
- 为规避 libc 内部递归，`stat` 族用直连系统调用；`realpath` 仅在确有需要时解析。

性能：无配置时各钩子走零成本快速路径；纯裸名配置几乎与不加载相当；目录列举使用
`d_ino` 快速过滤与线程内“干净目录”缓存，避免逐项 `stat`。

---

## 12. 已知限制

1. **`syscall()` 直接调用绕过所有钩子**（如部分 gnulib/coreutils 用原始 `renameat2`、`getdents64`）。
   这是 `LD_PRELOAD` 的固有边界。bionic 未导出 `getdents/getdents64`，无法钩。
2. `/proc/<pid>/mem`、`/proc/<pid>/pagemap` 是二进制、不含路径，无法做路径隐藏。
3. 钩子非 `async-signal-safe`（含 `malloc`/锁），**信号处理器内**调用有死锁/崩溃风险。
4. 运行期程序自行 `setenv/putenv` 的 `HIDE_*` 变量未被跟踪（仅跟踪 `LD_PRELOAD`）；`env` 可能短暂可见，
   但 `getenv` 与 execve 仍会处理。
5. “干净目录”缓存与路径条目 inode 身份在初始化时确定；运行期挂载/符号链接变化可能导致判定过期。
6. `MAXHIDE=64`、`MAXREDIR=32`、`MAXRPRE=32`、`MAXTOK=64`、`MAXDIRS=256` 为编译期上限，超出静默丢弃。
7. 目录映射表 `MAXDIRS` 满后，新目录不再记录，`readdir` 的绝对路径/`map_files` 过滤可能退化。
8. `env -i` 等自定义 envp 会被强制回注配置（隐藏无法绕过，属设计取舍）。

---

## 13. 自测

```sh
bash test_hide.sh
```

覆盖：配置隐藏、文件隐藏、重定向、双路径重定向回归、`HIDE_SO`（maps/smaps/自动隐藏）、
`/proc/mounts`、`statfs`、受限前缀等，共 16 项。

---

## 14. 常见问题（FAQ）

**Q：为什么 `ls` 看不到隐藏文件，但 `mv` 还能操作它？**
A：`HIDE_FILES` 通过钩子过滤，但某些程序用原始系统调用（绕过 libc 包装）会穿透；日常工具（ls/cat/rm 等）正常。

**Q：为什么隐藏 `/system/bin/sh` 后有些命令报 `Permission denied` / 回退到 `/vendor/bin/sh`？**
A：shell 的命令解析会用 `stat/access` 扫 PATH，隐藏使 `/system/bin/sh` 被跳过，于是回退到 PATH 里
其它 `sh`（如 `/vendor/bin/sh`），而 vendor 程序运行在受限 namespace。建议**不要隐藏 `/system/bin/sh`**，
需要替换行为时在 PATH 更靠前放一个**可见的** wrapper。

**Q：`execve` 会执行被隐藏/被重定向的文件吗？**
A：会执行字面路径——即被隐藏的原文件仍可执行；重定向对 `execve` 不生效。

**Q：如何只隐藏 `hide.so` 自身？**
A：不用配置。加载后会自动把 `LD_PRELOAD` 值 realpath 后加入 `HIDE_SO`，从 maps/smaps/map_files 中隐藏。

**Q：为什么设置的环境变量 `echo $HIDE_FILES` 是空的？**
A：这是设计：所有配置变量在构造期从自身环境原地删除，`env/getenv/printenv/echo` 都看不到。
