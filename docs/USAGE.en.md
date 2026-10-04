# hide.so — Usage Guide

[← README](../README.md) · [Design](DESIGN.md) · [License (GPL-3.0)](../LICENSE) · [中文](USAGE.md)

A single `LD_PRELOAD` shared library for Android (bionic) providing user-space **file hiding**,
**bind-style redirection**, and **`/proc` sanitization**. All configuration comes **only from
runtime environment variables** — there are no compile-time defaults, and every configured
variable is itself completely hidden.

> ⚠️ **Disclaimer**: This is dual-use technology. Use it only on devices you **own or are
> authorized to test**; do not use it to evade security controls, hide malware, or break the law.
> Root/`LD_PRELOAD` support is required; **use at your own risk**, no warranty of any kind.

---

## 1. Files and build

Repository contents:

| File | Description |
|---|---|
| `hide.c` | All source code |
| `hide.so` | Prebuilt library |
| `test_hide.sh` | One-shot self-test (build + 27 assertions) |
| `docs/USAGE.md` / `docs/USAGE.en.md` | This document |

Build:

```sh
clang -shared -fPIC -Wall -Wextra -O2 -o hide.so hide.c
```

Load (the **process that calls `execve` must have this library loaded** for the hooks to work):

```sh
# Option 1: only for the current command
LD_PRELOAD=/abs/path/hide.so <command>

# Option 2: for the whole session (recommended)
LD_PRELOAD=/abs/path/hide.so bash
# or
export LD_PRELOAD=/abs/path/hide.so
```

> Note: the value of `LD_PRELOAD` is itself the “exact target to hide”. The library reads it
> automatically (no extra configuration) and hides the corresponding library from
> `/proc/<pid>/maps` and friends.

---

## 2. Configuration overview

| Variable | Purpose | Format | When unset |
|---|---|---|---|
| `HIDE_FILES` | Hide files/dirs (**absolute paths only**) | `/a/b:/c/d` | hide nothing |
| `ALLOW_ACCESS` | Exempt from hiding for fstatat/faccessat/execve | `/a/b:/c/d` | no exemptions |
| `REDIRECT_FILES` | Bind-style redirect (incl. `execve` and xattr) | `src=dst[:...]` | no redirect |
| `HIDE_SO` | Hide libraries in maps/smaps/map_files | `lib.so:/path/lib.so` | auto-hide `LD_PRELOAD` only |
| `HIDE_MOUNT` | Hide mount points | `/data:/mnt/secret` | hide nothing |
| `SKIP_RESTRICTED_PATHS` | Prefixes never injected with `LD_PRELOAD` | `/vendor:/odm:...` | no skip |

All six variables, once set, are **completely hidden** (see §8).

> The v1.0 name `HIDE_RESTRICTED_PATHS` was renamed to `SKIP_RESTRICTED_PATHS`; the old name is
> neither parsed nor hidden.

---

## 3. HIDE_FILES — hide files/directories

Format: colon-separated list of **absolute paths**. **Only absolute paths are supported**:
non-absolute entries are ignored with a warning on stderr (expand them yourself).

Matching rules:

- a path matches **exactly**, or as a **directory prefix** on a `/` boundary (a directory match
  hides its whole subtree);
- entries are `realpath`-normalized at init; at runtime, exact/prefix string match comes first,
  then **inode identity** (`st_dev`+`st_ino`), which survives bind-mount aliases
  (e.g. `/data/data` ↔ `/data/user/0`) and symlinks;
- directory entries walk up parent inodes; a hit means “inside the hidden directory”;
- once hidden, `stat/lstat/access/open/opendir/readlink/rename/unlink/chmod/xattr/...` return
  `ENOENT`, and directory listings (`readdir/readdir64/scandir`) filter the entry out;
- **`execve` obeys hiding too**: a file matching `HIDE_FILES` and not listed in `ALLOW_ACCESS`
  cannot be executed (`ENOENT`). This changed from v1.0, where hidden files were still executable.

Examples:

```sh
# hide /data/tmp and /data/local/secret (including descendants)
LD_PRELOAD=./hide.so HIDE_FILES="/data/tmp:/data/local/secret" bash

# a targeted example (a specific file disappears)
LD_PRELOAD=./hide.so HIDE_FILES=/tmp/secret bash -c 'ls /tmp; cat /tmp/secret'
```

> Bare names (`name`) and relative paths (`./name`) are no longer supported; rewrite them as
> absolute paths.

---

## 4. ALLOW_ACCESS — allow-list

Format: colon-separated **absolute paths**; a directory entry covers its whole subtree (exact match,
or a sub-path on a `/` boundary). Non-absolute entries are ignored with a warning.

It affects **exactly two** things:

1. `fstatat`/`fstatat64`/`faccessat` probes:
   - if the operation hits a redirect, hiding is skipped (the target is reachable even if it is in
     `HIDE_FILES`);
   - otherwise the literal path is checked; only a match in the allow-list exempts it from `HIDE_FILES`;
2. `execve`: when the literal path is in the allow-list, it **executes the original path** —
   neither redirected nor hidden.

All other hooks (`stat`/`lstat`/`statx`/`access`/`open`/`readlink`/…) are **not** affected by
`ALLOW_ACCESS`; `HIDE_FILES` still applies to them.

> bionic has no `newfstatat` symbol; its semantics are those of `fstatat`/`fstatat64`.

Example:

```sh
# hide all of /data/local/secret, but allow probes/execution of /data/local/secret/keep
LD_PRELOAD=./hide.so HIDE_FILES=/data/local/secret \
  ALLOW_ACCESS=/data/local/secret/keep bash
```

---

## 5. REDIRECT_FILES — user-space bind redirect

Format: `src=dst`, colon-separated; split on the first `=`. Relative paths resolve with `dirfd`
semantics (via `/proc/self/fd`).

- `src` is a **file** → replaced exactly by `dst`;
- `src` is a **directory** → prefix replacement (`src/xxx` → `dst/xxx`);
- the first matching rule wins; rules are not chained.

Redirection is transparent for read/attribute/extended-attribute operations:
`stat/open/access/opendir/readlink/unlink/rename/chmod/utimes/truncate/creat/fopen/statfs/
getxattr/setxattr/listxattr/...`. **`execve` participates too**: a path matching `src` is rewritten
to `dst` before execution.

Priority: **when an operation hits a redirect, the `HIDE_FILES` check is skipped** — even if `dst`
is itself hidden, accessing it through `src` works (it is “this redirect’s target”). Direct access
to `dst` (no redirect) is still hidden as usual.

Extended attributes are rewritten as well, so the SELinux label (`security.selinux`) follows the
redirect and becomes `dst`’s label.

Examples:

```sh
# reading /etc/motd actually reads /data/motd.fake
LD_PRELOAD=./hide.so REDIRECT_FILES="/etc/motd=/data/motd.fake" cat /etc/motd

# redirect a whole directory
LD_PRELOAD=./hide.so REDIRECT_FILES="/sdcard/secure=/data/local/secure" ls /sdcard/secure

# the target is itself hidden, but reachable via src; direct access to dst stays hidden
LD_PRELOAD=./hide.so HIDE_FILES=/data/real \
  REDIRECT_FILES="/data/alias=/data/real" cat /data/alias
```

---

## 6. HIDE_SO — hide dynamic library paths

Scope:

- `/proc/<pid>/maps`, `/proc/<pid>/smaps`, `/proc/<pid>/smaps_rollup` (line filtering)
- `/proc/<pid>/map_files` (filter symlink targets, incl. direct `open/stat/readlink` by address)

Format: colon-separated match items.

- Entries containing `/` are first **`realpath`-canonicalized**, so they match the absolute paths
  shown in `maps`;
- bare names match on path-component boundaries;
- **the `LD_PRELOAD` library itself is always added automatically** (its value realpath’d), so
  `hide.so` is hidden without any configuration.

Example:

```sh
# additionally hide another library
LD_PRELOAD=./hide.so HIDE_SO="libtarget.so:./tmp.so" bash
# those paths disappear from maps/smaps/map_files
```

Matching boundaries: a hit must be a “path component/prefix”, with the left boundary at start of
string, `/`, or whitespace, and the right boundary at end of string, `/`, or whitespace (whitespace
tolerates the `" (deleted)"` suffix in maps). So `libc.so` hides only a component actually named
`libc.so` and will not over-match on `libc`.

---

## 7. HIDE_MOUNT — hide mount information

Scope:

- `/proc/<pid>/mounts`, `/proc/<pid>/mountinfo`, `/proc/<pid>/mountstat`, `/proc/<pid>/mountstats`
  (the no-pid forms such as `/proc/mounts` are supported too)
- `statfs`/`statfs64`/`statvfs`/`statvfs64`: hidden mount points return `ENOENT`
- `umount`/`umount2`: hidden mount points return `EINVAL` (a direct `syscall(SYS_umount2,...)`
  cannot be intercepted)

Format: colon-separated paths; match a mount point **exactly** or as a **prefix** (`/a` matches
`/a` and `/a/...`).

> Note: this does not affect directory listings — `readdir`/`scandir` still list the mount point.

Example:

```sh
LD_PRELOAD=./hide.so HIDE_MOUNT="/data:/mnt/secret" bash
cat /proc/self/mounts   # /data etc. disappear
stat -f /data           # fails (ENOENT)
umount /data            # fails (EINVAL)
```

---

## 8. Self-hiding of configuration variables

Every configured variable (`HIDE_FILES`, `ALLOW_ACCESS`, `REDIRECT_FILES`, `SKIP_RESTRICTED_PATHS`,
`HIDE_SO`, `HIDE_MOUNT`, and `LD_PRELOAD` when it equals the target) is:

1. **removed in place from the process `environ` array** at construction
   (shift + NULL, not `unsetenv`): `echo $VAR`, `env`, `printenv`, `env | grep` cannot see it;
2. hidden from `getenv()` / `secure_getenv()` (returns `NULL`);
3. sanitized when `/proc/<pid>/environ` is read (a `memfd` returns the filtered content);
4. **re-injected on execve into dynamic children**, so children still load `hide.so` and inherit config;
5. **stripped (not re-injected) for static / `SKIP_RESTRICTED_PATHS` targets**, to avoid leaks.

> Note: children “re-inject, then remove in place in their constructor”, recursively and stably.
> Configuration is read by scanning `environ` directly at construction — not via `dlsym(getenv)` —
> so nothing can be missed and leak.

---

## 9. SKIP_RESTRICTED_PATHS — restricted linker namespace

On Android, executables in `/vendor`, `/odm`, `/product`, `/system_ext`, `/apex`, … run in a
restricted linker namespace whose `permitted_paths` does not allow injecting `LD_PRELOAD` from
`/data`. Otherwise you get:

```
WARNING: linker: library ... is not accessible for the namespace ...
CANNOT LINK EXECUTABLE ...: library ... is not accessible for the namespace
```

So such targets must not be injected. List the prefixes (named `HIDE_RESTRICTED_PATHS` in v1.0):

```sh
LD_PRELOAD=./hide.so SKIP_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" bash
```

On a match (prefix-boundary match): `LD_PRELOAD` and all configuration are stripped, nothing is
injected, exactly like a static target. When unset, there is no restriction — on Android you are
strongly advised to set the value above.

> Matching works on the lexically absolutized literal path and no longer falls back to `realpath`
> for symlinks; if an executable is a symlink whose real target lies in a restricted prefix, list
> the symlink’s prefix as well.

---

## 10. execve behaviour summary

- **Hidden**: a file matching `HIDE_FILES` and not in `ALLOW_ACCESS` cannot be executed (`ENOENT`).
- **Redirected**: the path is rewritten per `REDIRECT_FILES` first; a redirect match skips the hiding
  check for this operation.
- `ALLOW_ACCESS` takes precedence: a literal path in the allow-list runs the original path, neither
  redirected nor hidden.
- Environment handling:
  - target is **statically linked** (no `PT_INTERP`, including shebang resolution) → strip all config;
  - target is in a **`SKIP_RESTRICTED_PATHS` prefix** → strip all config;
  - target is **dynamic and guaranteed to load hide.so** (the current `LD_PRELOAD` target is in
    effect) → re-inject config;
  - this process was **not loaded via `LD_PRELOAD`** (cannot guarantee children load hide.so)
    → strip only, no re-injection, to avoid leaks.
- If environment rebuilding fails to allocate, it **fails closed** (returns `ENOMEM`) rather than
  passing unsanitized configuration to the child.
- If a program modifies `LD_PRELOAD` at runtime (`setenv`/`putenv`/`unsetenv`/`clearenv`, or
  directly changes envp such as bash `export`) to a value different from the current target →
  the library **stops managing** `LD_PRELOAD` (no strip/re-inject) and respects the user’s setting.

---

## 11. Combined example

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

## 12. How it works

- Hooks obtain the real functions via `dlsym(RTLD_NEXT, ...)`; the `GET_REAL` macro unifies lazy
  loading (serialized with a mutex) and degrades to `ENOSYS` instead of aborting when a symbol is
  missing.
- Path matching prefers “zero-syscall” lexical normalization (with a fast path for absolute paths
  that contain no `.`/`..`); inode identity uses a direct `fstatat` syscall, and path entries are
  sorted by length for early exit.
- Redirection writes the rewritten path into a **stack `alloca` buffer** (per call, so multiple
  paths / re-entrant hooks cannot clobber each other); the target is tracked in TLS so nested hooks
  (`stat→fstatat`, `realpath→lstat`) skip hiding for the duration of the operation.
- `/proc` text is sanitized by **streaming** into a `memfd`, coalescing writes in 64 KiB chunks and
  keeping only one incomplete tail segment; a segment over 8 MiB or a write failure **fails closed**
  (never returns the raw content).
- `map_files` matches `HIDE_SO` via the `readlinkat` target.
- To avoid libc-internal recursion, the `stat` family uses direct syscalls; `realpath` is only
  used when truly needed.
- Most hooks are generated by `W_*` macros (path / two-path / at variants) that uniformly perform
  “redirect → hide decision → real call”.

Performance: with no configuration, every hook takes a zero-cost fast path; path entries are
length-sorted and ancestor walk is allocation-free; directory listing uses `d_ino` fast filtering
and a per-thread “clean directory” cache to avoid per-entry `stat`; the directory map evicts
oldest-first (FIFO) when full, so recently opened directories stay tracked.

---

## 13. Known limitations

1. **`HIDE_FILES` accepts absolute paths only**; bare names/relative paths are ignored with a
   warning. Relative paths must be expanded by the caller.
2. **A direct `syscall()` bypasses all hooks** (e.g. some gnulib/coreutils use raw `renameat2` or
   `getdents64`). This is inherent to `LD_PRELOAD`. bionic does not export
   `getdents`/`getdents64`, so they cannot be hooked.
3. `/proc/<pid>/mem` and `/proc/<pid>/pagemap` are binary and carry no paths; no path hiding.
4. Hooks are **not async-signal-safe** (they use `malloc`/locks); calling them from a signal
   handler risks deadlock/crash.
5. `HIDE_*` variables set at runtime by a program (`setenv`/`putenv`) are not tracked (only
   `LD_PRELOAD` is); `env` may briefly see them, but `getenv` and execve still handle them.
6. The “clean directory” cache, path-entry inode identities and `ALLOW_ACCESS` lexical expansion are
   fixed at init; runtime mount/symlink changes can make the verdicts stale.
7. `MAXHIDE=64`, `MAXALLOW=64`, `MAXREDIR=32`, `MAXRPRE=32`, `MAXTOK=64`, `MAXDIRS=256` are
   compile-time limits; overflow is silently dropped (the directory map evicts FIFO when full).
8. `HIDE_MOUNT` does not affect `readdir`/`scandir` listings; it only filters `/proc` mount info
   and statfs/umount.
9. Custom envp such as `env -i` is forcibly re-injected with configuration (hiding cannot be
   bypassed; a deliberate trade-off).

---

## 14. Self-test

```sh
bash test_hide.sh
```

Covers: config hiding, absolute-path hiding, relative-entry rejection, `ALLOW_ACCESS`
(fstatat/faccessat/execve), redirection (hidden target reachable, `execve` redirect, two-path
regression), `HIDE_SO` (maps/smaps/auto-hide), `/proc/mounts`, `statfs`, `SKIP_RESTRICTED_PATHS`,
etc. — 27 assertions.

---

## 15. FAQ

**Q: Why can `ls` no longer see a hidden file, but `mv` can still operate on it?**
A: `HIDE_FILES` filters via hooks, but some programs issue raw system calls (bypassing the libc
wrappers); everyday tools (ls/cat/rm) behave correctly.

**Q: Why does `HIDE_FILES=secret` have no effect?**
A: Since this release, `HIDE_FILES` accepts absolute paths only; bare names/relative paths are ignored with
a warning on stderr. Write the full absolute path.

**Q: Why do some commands report `Permission denied` or fall back to `/vendor/bin/sh` after
hiding `/system/bin/sh`?**
A: Shell command resolution scans `PATH` with `stat`/`access`; hiding makes `/system/bin/sh`
skipped, so it falls back to another `sh` later in `PATH` (e.g. `/vendor/bin/sh`), and vendor
binaries run in a restricted namespace. It is recommended **not to hide `/system/bin/sh`**; to
change behaviour, put a **visible** wrapper earlier in `PATH`.

**Q: Will `execve` execute a hidden/redirected file?**
A: A hidden file is **not** executable by default (`ENOENT`) unless listed in `ALLOW_ACCESS`;
redirection **does** apply to `execve`, so a path matching `src` executes `dst`.

**Q: How do I hide only `hide.so` itself?**
A: No configuration needed. After loading, the `LD_PRELOAD` value is realpath’d and added to
`HIDE_SO` automatically, hiding it from maps/smaps/map_files.

**Q: Why is the configured `echo $HIDE_FILES` empty?**
A: By design: every configured variable is removed in place from the process environment at
construction, so `env/getenv/printenv/echo` cannot see it.

**Q: Can I still use the old `HIDE_RESTRICTED_PATHS`?**
A: No. It was renamed to `SKIP_RESTRICTED_PATHS`; the old name is neither parsed nor hidden —
switch to the new name.
