# hide.so

> User-space file hiding, bind-style redirection, and `/proc` sanitization for Android (bionic), implemented as a single `LD_PRELOAD` shared library.

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Android%20(bionic)-green.svg)
![Language](https://img.shields.io/badge/language-C99-orange.svg)

**English** | [中文](#中文说明)

---

## ⚠️ Disclaimer

This project uses `LD_PRELOAD` interposition to hide files, redirect paths, and modify what
`/proc/<pid>/{maps,mounts,environ}` report. Such techniques are **dual-use**.

- Use it **only on devices you own or are explicitly authorized to test**.
- Do **not** use it to evade security controls, hide malware, or violate laws.
- Requires root/`LD_PRELOAD` support; **you are responsible for any damage**.
- Provided **as-is**, without warranty. See [`LICENSE`](LICENSE) (GPL-3.0).

If you do not agree, do not use this software.

---

## Features

- **Hide files/dirs** (`HIDE_FILES`) — **absolute paths only**; a directory match hides its whole
  subtree. Matching combines lexical prefix and inode identity, so it survives bind-mount aliases
  (`/data/data` ↔ `/data/user/0`) and symlinks. Hidden paths return `ENOENT` and cannot be executed.
- **Allow-list** (`ALLOW_ACCESS`) — absolute paths exempted from `HIDE_FILES` for
  `fstatat`/`fstatat64`/`faccessat` probes and `execve`; directory entries cover the whole subtree.
- **Bind-style redirection** (`REDIRECT_FILES`) — transparently rewrite paths for
  `stat/open/access/readlink/xattr/...` **and `execve`**; files exact-match, directories
  prefix-match. A redirect target stays reachable even when it is itself hidden.
- **Hide libraries** (`HIDE_SO`) — remove matching paths from `/proc/<pid>/{maps,smaps,smaps_rollup}`
  and `/proc/<pid>/map_files`; `LD_PRELOAD` itself is hidden automatically.
- **Hide mounts** (`HIDE_MOUNT`) — filter `/proc/<pid>/{mounts,mountinfo,mountstat[s]}` and make
  `statfs`/`statvfs` fail with `ENOENT` and `umount`/`umount2` fail with `EINVAL` for hidden mounts.
- **Restricted-namespace safety** (`SKIP_RESTRICTED_PATHS`) — never inject into `/vendor`, `/odm`, … binaries.
- **Self-hiding config** — every configured variable is removed from the process environment and
  redacted from `/proc/<pid>/environ`; `getenv`/`env`/`printenv`/`echo` cannot see it, while dynamic
  children transparently inherit it.
- **No compile-time defaults** — everything is runtime-configured.
- **Zero-cost fast paths** when a feature is not configured.

## How it works

The library interposes libc wrappers (`stat`, `open`, `readdir`, `execve`, xattr, `getenv`, …) via
`dlsym(RTLD_NEXT, ...)`. Path matching is done lexically with direct `fstatat` syscalls for inode
identity; `/proc` text files are filtered streamingly into a `memfd`; maps/map_files use link-target
matching. See [`docs/DESIGN.md`](docs/DESIGN.md).

## Requirements

- Android with bionic (tested on Android 12–16, arm64-v8a).
- Toolchain: Termux `clang`, or Android NDK (`r25+`).
- Root or a way to pass `LD_PRELOAD` to target processes.

## Build

### Termux / on-device

```sh
clang -shared -fPIC -Wall -Wextra -O2 -o hide.so hide.c
```

### Android NDK (cross compile, recommended for release)

```sh
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
  -shared -fPIC -Wall -Wextra -O2 -o hide.so hide.c
```

### CMake

```cmake
cmake_minimum_required(VERSION 3.20)
project(hide C)
add_library(hide SHARED hide.c)
set_target_properties(hide PROPERTIES PREFIX "" OUTPUT_NAME "hide")
target_compile_options(hide PRIVATE -Wall -Wextra -O2)
```

## Quick start

The process that calls `execve` must itself have `hide.so` loaded.

```sh
# Load into a shell session
LD_PRELOAD=$PWD/hide.so bash

# Hide a directory tree, allow one path inside it for probes/exec,
# redirect a file, and keep vendor binaries un-injected
LD_PRELOAD=$PWD/hide.so \
HIDE_FILES="/data/tmp:/data/local/secret" \
ALLOW_ACCESS="/data/local/secret/keep" \
REDIRECT_FILES="/etc/motd=/data/local/motd.fake" \
SKIP_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" \
bash
```

## Configuration

| Variable | Purpose | Format | Unset |
|---|---|---|---|
| `HIDE_FILES` | Hide files/dirs (absolute paths only) | `/a/b:/c/d` | hide nothing |
| `ALLOW_ACCESS` | Exempt paths from hiding for `fstatat`/`faccessat` + `execve` | `/a/b:/c/d` | no exemptions |
| `REDIRECT_FILES` | Bind-style redirect (incl. `execve` and xattr) | `src=dst[:...]` | no redirect |
| `HIDE_SO` | Hide libs in maps/smaps/map_files | `lib.so:/path/lib.so` | auto-hide `LD_PRELOAD` only |
| `HIDE_MOUNT` | Hide mount points | `/data:/mnt/secret` | hide nothing |
| `SKIP_RESTRICTED_PATHS` | Paths never injected with `LD_PRELOAD` | `/vendor:/odm:...` | no skip |

Full details, matching rules and examples: [`docs/USAGE.en.md`](docs/USAGE.en.md) (English)
· [`docs/USAGE.md`](docs/USAGE.md) (中文).

## Limitations

- `HIDE_FILES` accepts **absolute paths only**; bare names and relative paths are ignored (with a
  warning on stderr). Expand them to absolute paths yourself.
- `HIDE_MOUNT` does not remove entries from directory listings (`readdir`/`scandir`).
- Raw `syscall()` bypasses all hooks (e.g. some tools use `renameat2`/`getdents64` directly).
  This is inherent to `LD_PRELOAD`. bionic does not export `getdents`/`getdents64`.
- `/proc/<pid>/mem` and `/proc/<pid>/pagemap` are binary and carry no paths.
- Hooks are not async-signal-safe (they use `malloc`/locks).
- `HIDE_RESTRICTED_PATHS` (v1.0) was renamed to `SKIP_RESTRICTED_PATHS`; the old name is neither
  parsed nor hidden.
- See [`docs/USAGE.md` § Limitations](docs/USAGE.md) for the full list.

## Testing

```sh
bash test_hide.sh   # builds and runs 27 assertions
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Please read the Disclaimer first.

## License

GNU General Public License v3.0 — see [`LICENSE`](LICENSE).

Copyright (C) 2026 null07089.

---

## 中文说明

> 基于 `LD_PRELOAD` 的 Android（bionic）用户态“文件隐身 + 重定向 + `/proc` 脱敏”单文件动态库。

### ⚠️ 免责声明

本技术为**双用途**：请仅在**你拥有或获授权测试**的设备上使用；**不得**用于规避安全控制、
隐藏恶意程序或违反法律。需要 root/`LD_PRELOAD` 支持，**后果自负**，**不提供任何担保**。
详见 [`LICENSE`](LICENSE)（GPL-3.0）。

### 功能

- `HIDE_FILES` 隐藏文件/目录（**仅绝对路径**；目录命中连带整棵子树）。词法前缀 + inode 身份匹配，
  可跨绑定挂载别名（`/data/data` ↔ `/data/user/0`）与符号链接；隐藏后不可打开，也不可执行。
- `ALLOW_ACCESS` 放行名单（绝对路径）：豁免 `fstatat`/`fstatat64`/`faccessat` 探测与 `execve` 上的
  `HIDE_FILES` 判定；目录条目对整棵子树生效。
- `REDIRECT_FILES` 用户态 bind 重定向：读/stat/open/xattr **及 `execve`** 全面透明改写；
  命中重定向时，目标即使本身在隐藏名单中也可达。
- `HIDE_SO` 从 `maps/smaps/map_files` 隐藏库路径；自动隐藏 `LD_PRELOAD` 自身。
- `HIDE_MOUNT` 隐藏挂载信息：`statfs`/`statvfs` 返回 `ENOENT`，`umount`/`umount2` 返回 `EINVAL`。
- `SKIP_RESTRICTED_PATHS` 受限 linker namespace 保护（v1.0 的 `HIDE_RESTRICTED_PATHS` 更名而来）。
- 配置变量**彻底自隐藏**：`env`/`printenv`/`echo`/`getenv`/`/proc/<pid>/environ` 均不可见，
  动态子进程自动回注继承；静态目标与 `SKIP_RESTRICTED_PATHS` 命中目标剥离。
- **无编译期默认**，全部运行时环境变量配置。

### 构建

```sh
clang -shared -fPIC -Wall -Wextra -O2 -o hide.so hide.c
# 或 NDK：
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
  -shared -fPIC -Wall -Wextra -O2 -o hide.so hide.c
```

### 快速开始

```sh
LD_PRELOAD=$PWD/hide.so \
HIDE_FILES="/data/tmp:/data/local/secret" \
ALLOW_ACCESS="/data/local/secret/keep" \
REDIRECT_FILES="/etc/motd=/data/local/motd.fake" \
SKIP_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" \
bash
```

### 完整文档

详见 [`docs/USAGE.md`](docs/USAGE.md)（中文） · [`docs/USAGE.en.md`](docs/USAGE.en.md)（English）
—— 配置详解、匹配规则、示例、限制、FAQ。
