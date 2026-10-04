# Contributing

Thanks for your interest. Please read the [Disclaimer](README.md#️-disclaimer) first:
this project is dual-use and must only be used on devices you own or are authorized to test.

## Ground rules

- Be respectful. Harassment and abuse are not tolerated.
- Do not submit code whose primary purpose is malicious (e.g. hiding malware, evading EDR).
- All contributions are licensed under **GPL-3.0** (see [`LICENSE`](LICENSE)).

## Development

### Build

```sh
# on-device / Termux
clang -shared -fPIC -Wall -Wextra -O2 -o hide.so hide.c

# NDK
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
  -shared -fPIC -Wall -Wextra -O2 -o hide.so hide.c
```

### Test

```sh
bash test_hide.sh
```

The test builds `hide.so` in a temporary directory and runs 27 assertions covering configuration
self-hiding, absolute-path file hiding, `ALLOW_ACCESS` (fstatat/faccessat/execve), redirection
(including hidden-target reachability and `execve` redirect), `HIDE_SO`, `HIDE_MOUNT`
(`/proc/mounts`, `statfs`), and `SKIP_RESTRICTED_PATHS`. Please add a case for any bug fix or new
feature.

### Style

- C99, `-Wall -Wextra` clean.
- No comments unless they add real value; keep them concise and in the existing style.
- Prefer zero-allocation, zero-syscall fast paths on hot hooks.
- Do not add compile-time configuration defaults; configuration must be runtime-only.

## Pull requests

1. Fork, create a topic branch.
2. Keep changes focused; update `docs/USAGE.md` / `docs/DESIGN.md` and `CHANGELOG.md` when relevant.
3. Ensure `bash test_hide.sh` passes and the build is warning-free.
4. Fill in the PR template, including a short description and test evidence.

## Reporting bugs

Use the bug report template and include:

- Android version and ABI, device/ROM, root method;
- toolchain and exact build command;
- minimal reproduction (config variables + commands);
- expected vs actual behavior, and relevant logs.

## Security

If you find a vulnerability, please open a private security advisory rather than a public issue.
