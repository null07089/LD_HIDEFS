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

- **Hide files/dirs** (`HIDE_FILES`) — by name, relative path, or absolute path (with directory
  prefix + inode identity matching that survives bind-mount aliases like `/data/data` ↔ `/data/user/0`).
- **Bind-style redirection** (`REDIRECT_FILES`) — transparently rewrite paths for read/stat/open/…,
  files exact-match, directories prefix-match. `execve` is intentionally **not** redirected.
- **Hide libraries** (`HIDE_SO`) — remove matching paths from `/proc/<pid>/{maps,smaps,smaps_rollup}`
  and `/proc/<pid>/map_files`; `LD_PRELOAD` itself is hidden automatically.
- **Hide mounts** (`HIDE_MOUNT`) — filter `/proc/<pid>/{mounts,mountinfo,mountstat[s]}` and make
  `statfs`/`statvfs` fail for hidden mount points.
- **Restricted-namespace safety** (`HIDE_RESTRICTED_PATHS`) — never inject into `/vendor`, `/odm`, … binaries.
- **Self-hiding config** — every configured variable is removed from the process environment and
  redacted from `/proc/<pid>/environ`; `getenv`/`env`/`printenv`/`echo` cannot see it, while dynamic
  children transparently inherit it.
- **No compile-time defaults** — everything is runtime-configured.
- **Zero-cost fast paths** when a feature is not configured.

## How it works

The library interposes libc wrappers (`stat`, `open`, `readdir`, `execve`, `getenv`, …) via
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

# Hide a file and a directory tree, and redirect another file
LD_PRELOAD=$PWD/hide.so \
HIDE_FILES="secret:./local:/data/system/sh_raw" \
REDIRECT_FILES="/etc/motd=/data/local/motd.fake" \
HIDE_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" \
bash
```

## Configuration

| Variable | Purpose | Format | Unset |
|---|---|---|---|
| `HIDE_FILES` | Hide files/dirs | `name:./rel:/abs` | hide nothing |
| `REDIRECT_FILES` | Bind-style redirect | `src=dst[:...]` | no redirect |
| `HIDE_SO` | Hide libs in maps/smaps/map_files | `lib.so:/path/lib.so` | auto-hide `LD_PRELOAD` only |
| `HIDE_MOUNT` | Hide mount points | `/data:/mnt/secret` | hide nothing |
| `HIDE_RESTRICTED_PATHS` | Restricted linker-namespace prefixes | `/vendor:/odm:...` | no restriction |

Full details, matching rules and examples: [`docs/USAGE.en.md`](docs/USAGE.en.md) (English)
· [`docs/USAGE.md`](docs/USAGE.md) (中文).

## Limitations

- Raw `syscall()` bypasses all hooks (e.g. some tools use `renameat2`/`getdents64` directly).
  This is inherent to `LD_PRELOAD`. bionic does not export `getdents`/`getdents64`.
- `/proc/<pid>/mem` and `/proc/<pid>/pagemap` are binary and carry no paths.
- Hooks are not async-signal-safe (they use `malloc`/locks).
- See [`docs/USAGE.md` § Limitations](docs/USAGE.md) for the full list.

## Testing

```sh
bash test_hide.sh   # builds and runs 16 assertions
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Please read the Disclaimer first.

## License

GNU General Public License v3.0 — see [`LICENSE`](LICENSE).

github@null07089 (C) 2026 hide.so contributors.

---

## 中文说明

> 基于 `LD_PRELOAD` 的 Android（bionic）用户态“文件隐身 + 重定向 + `/proc` 脱敏”单文件动态库。

### ⚠️ 免责声明

本技术为**双用途**：请仅在**你拥有或获授权测试**的设备上使用；**不得**用于规避安全控制、
隐藏恶意程序或违反法律。需要 root/`LD_PRELOAD` 支持，**后果自负**，**不提供任何担保**。
详见 [`LICENSE`](LICENSE)（GPL-3.0）。

### 功能

- `HIDE_FILES` 隐藏文件/目录（裸名/相对/绝对；目录前缀 + inode 身份，可跨绑定挂载别名）。
- `REDIRECT_FILES` 用户态 bind 重定向（读/stat/open 等透明改写；`execve` 不参与重定向）。
- `HIDE_SO` 从 `maps/smaps/map_files` 隐藏库路径；自动隐藏 `LD_PRELOAD` 自身。
- `HIDE_MOUNT` 隐藏挂载信息，并让 `statfs`/`statvfs` 对隐藏挂载点返回 `ENOENT`。
- `HIDE_RESTRICTED_PATHS` 受限 linker namespace 保护，避免注入 `/vendor` 等致命错误。
- 配置变量**彻底自隐藏**：`env`/`printenv`/`echo`/`getenv`/`/proc/<pid>/environ` 均不可见，
  动态子进程自动回注继承。
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
HIDE_FILES="secret:/data/system/sh_raw" \
REDIRECT_FILES="/etc/motd=/data/local/motd.fake" \
HIDE_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" \
bash
```

### 完整文档

详见 [`docs/USAGE.md`](docs/USAGE.md)（中文） · [`docs/USAGE.en.md`](docs/USAGE.en.md)（English）
—— 配置详解、匹配规则、示例、限制、FAQ。
