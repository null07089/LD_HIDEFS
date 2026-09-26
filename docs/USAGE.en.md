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
| `test_hide.sh` | One-shot self-test (build + 16 assertions) |
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
| `HIDE_FILES` | Hide files/dirs | `name:./rel:/abs` | hide nothing |
| `REDIRECT_FILES` | Bind-style redirect | `src=dst[:...]` | no redirect |
| `HIDE_SO` | Hide libraries in maps/smaps/map_files | `lib.so:/path/lib.so` | auto-hide `LD_PRELOAD` only |
| `HIDE_MOUNT` | Hide mount points | `/data:/mnt/secret` | hide nothing |
| `HIDE_RESTRICTED_PATHS` | Restricted linker-namespace prefixes | `/vendor:/odm:...` | no restriction (recommended on Android) |

All five variables, once set, are **completely hidden** (see §7).

---

## 3. HIDE_FILES — hide files/directories

Format: colon-separated; each entry has one of three forms:

| Form | Meaning |
|---|---|
| `name` | **Bare name**: hide anywhere a path component equals it (global) |
| `./name` | **Relative path**: hide only the entry under the process cwd at init time |
| `/a/b/name` | **Absolute path**: hide exactly this path; if it is a directory, **all descendants** too |

Matching notes:

- Bare names match a **whole path component** (`namex` does not match `name`).
- Path entries are `realpath`-normalized at init; at runtime:
  - exact/prefix string match first;
  - then **inode identity** (`st_dev`+`st_ino`), which survives bind-mount aliases
    (e.g. `/data/data` ↔ `/data/user/0`) and symlinks;
  - directory entries walk up parent inodes; a hit means “inside the hidden directory”.
- Once hidden, `stat/lstat/access/open/opendir/readlink/rename/unlink/chmod/...` return `ENOENT`,
  and directory listings (`readdir/readdir64/scandir`) filter the entry out.

Examples:

```sh
LD_PRELOAD=./hide.so HIDE_FILES="secret:./local:/data/system/sh_raw" bash
```

A targeted example (a specific file disappears):

```sh
LD_PRELOAD=./hide.so HIDE_FILES=/tmp/secret bash -c 'ls /tmp; cat /tmp/secret'
```

---

## 4. REDIRECT_FILES — user-space bind redirect

Format: `src=dst`, colon-separated; split on the first `=`.

- `src` is a **file** → replaced exactly by `dst`;
- `src` is a **directory** → prefix replacement (`src/xxx` → `dst/xxx`).

Redirection is transparent for read/write-class operations:
`stat/open/access/opendir/readlink/unlink/rename/chmod/utimes/truncate/creat/fopen/statfs/...`.

Examples:

```sh
# reading /etc/motd actually reads /data/motd.fake
LD_PRELOAD=./hide.so REDIRECT_FILES="/etc/motd=/data/motd.fake" cat /etc/motd

# redirect a whole directory
LD_PRELOAD=./hide.so REDIRECT_FILES="/sdcard/secure=/data/local/secure" ls /sdcard/secure
```

### Important exception: `execve` is not redirected

- `execve` always executes the **literal path**, so it can also execute a file hidden by `HIDE_FILES`.
- Hence “redirect `/system/bin/sh` to my own wrapper” is **not** achieved via redirection; the
  reliable approach is to place a **visible** wrapper earlier in `PATH`, or call an absolute path.
- A rule `a=b` only turns “reading a” into “reading b”; it does not affect executing b.

---

## 5. HIDE_SO — hide dynamic library paths

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
LD_PRELOAD=./hide.so HIDE_SO="libtarget.so:/data/system/other.so" bash
# those paths disappear from maps/smaps/map_files
```

Matching boundaries: a hit must be a “path component/prefix”, with the left boundary at start of
string, `/`, or whitespace, and the right boundary at end of string, `/`, or whitespace (whitespace
tolerates the `" (deleted)"` suffix in maps). So `libc.so` hides only a component actually named
`libc.so` and will not over-match on `libc`.

---

## 6. HIDE_MOUNT — hide mount information

Scope:

- `/proc/<pid>/mounts`, `/proc/<pid>/mountinfo`, `/proc/<pid>/mountstat`, `/proc/<pid>/mountstats`
  (the no-pid forms such as `/proc/mounts` are supported too)
- `statfs`/`statfs64`/`statvfs`/`statvfs64`: hidden mount points return `ENOENT`

Format: colon-separated paths; match a mount point **exactly** or as a **prefix** (`/a` matches
`/a` and `/a/...`).

Example:

```sh
LD_PRELOAD=./hide.so HIDE_MOUNT="/data:/mnt/secret" bash
cat /proc/self/mounts   # /data etc. disappear
stat -f /data           # fails (ENOENT)
```

---

## 7. Self-hiding of configuration variables

Every configured variable (`HIDE_FILES`, `REDIRECT_FILES`, `HIDE_RESTRICTED_PATHS`, `HIDE_SO`,
`HIDE_MOUNT`, and `LD_PRELOAD` when it equals the target) is:

1. **removed in place from the process `environ` array** at construction
   (shift + NULL, not `unsetenv`): `echo $VAR`, `env`, `printenv`, `env | grep` cannot see it;
2. hidden from `getenv()` / `secure_getenv()` (returns `NULL`);
3. sanitized when `/proc/<pid>/environ` is read (a `memfd` returns the filtered content);
4. **re-injected on execve into dynamic children**, so children still load `hide.so` and inherit config;
5. **stripped (not re-injected) for static / restricted-namespace targets**, to avoid leaks.

> Note: children “re-inject, then remove in place in their constructor”, recursively and stably.

---

## 8. HIDE_RESTRICTED_PATHS — restricted linker namespace

On Android, executables in `/vendor`, `/odm`, `/product`, `/system_ext`, `/apex`, … run in a
restricted linker namespace whose `permitted_paths` does not allow injecting `LD_PRELOAD` from
`/data`. Otherwise you get:

```
WARNING: linker: library ... is not accessible for the namespace ...
CANNOT LINK EXECUTABLE ...: library ... is not accessible for the namespace
```

So such targets must not be injected. List the prefixes:

```sh
LD_PRELOAD=./hide.so HIDE_RESTRICTED_PATHS="/vendor:/odm:/product:/system_ext:/apex" bash
```

On a match (prefix-boundary match): `LD_PRELOAD` and all configuration are stripped, nothing is
injected. When unset, there is no restriction — on Android you are strongly advised to set the
value above.

---

## 9. execve behaviour summary

- **Not hidden**: it can execute files hidden by `HIDE_FILES` (hiding only affects reads and listings).
- **Not redirected**: it executes the literal path.
- It does environment handling:
  - target is **statically linked** (no `PT_INTERP`, including shebang resolution) → strip all config;
  - target is in a **restricted namespace** → strip all config;
  - target is **dynamic and guaranteed to load hide.so** (the current `LD_PRELOAD` target is in
    effect) → re-inject config;
  - this process was **not loaded via `LD_PRELOAD`** (cannot guarantee children load hide.so)
    → strip only, no re-injection, to avoid leaks.
- If a program modifies `LD_PRELOAD` at runtime (`setenv`/`putenv`/`unsetenv`/`clearenv`, or
  directly changes envp such as bash `export`) to a value different from the current target →
  the library **stops managing** `LD_PRELOAD` (no strip/re-inject) and respects the user’s setting.

---

## 10. Combined example

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

## 11. How it works

- Hooks obtain the real functions via `dlsym(RTLD_NEXT, ...)`; the `GET_REAL` macro unifies lazy
  loading (serialized with a mutex).
- Path matching prefers “zero-syscall” lexical normalization; inode identity uses a direct `fstatat`
  syscall.
- Redirection writes the rewritten path into a **stack `alloca` buffer** (per call, so multiple
  paths / re-entrant hooks cannot clobber each other).
- `/proc` text is sanitized by **streaming** into a `memfd`, keeping only one incomplete tail
  segment; it fails closed (never returns the raw content).
- `map_files` matches `HIDE_SO` via the `readlinkat` target.
- To avoid libc-internal recursion, the `stat` family uses direct syscalls; `realpath` is only
  used when truly needed.

Performance: with no configuration, every hook takes a zero-cost fast path; a bare-name-only
configuration is nearly as fast as not loading `hide.so`; directory listing uses `d_ino` fast
filtering and a per-thread “clean directory” cache to avoid per-entry `stat`.

---

## 12. Known limitations

1. **A direct `syscall()` bypasses all hooks** (e.g. some gnulib/coreutils use raw `renameat2` or
   `getdents64`). This is inherent to `LD_PRELOAD`. bionic does not export
   `getdents`/`getdents64`, so they cannot be hooked.
2. `/proc/<pid>/mem` and `/proc/<pid>/pagemap` are binary and carry no paths; no path hiding.
3. Hooks are **not async-signal-safe** (they use `malloc`/locks); calling them from a signal
   handler risks deadlock/crash.
4. `HIDE_*` variables set at runtime by a program (`setenv`/`putenv`) are not tracked (only
   `LD_PRELOAD` is); `env` may briefly see them, but `getenv` and execve still handle them.
5. The “clean directory” cache and path-entry inode identities are fixed at init; runtime
   mount/symlink changes can make the verdicts stale.
6. `MAXHIDE=64`, `MAXREDIR=32`, `MAXRPRE=32`, `MAXTOK=64`, `MAXDIRS=256` are compile-time limits;
   overflow is silently dropped.
7. Once the directory map (`MAXDIRS`) is full, new directories are not recorded, and the
   absolute-path/`map_files` filtering in `readdir` may degrade.
8. Custom envp such as `env -i` is forcibly re-injected with configuration (hiding cannot be
   bypassed; a deliberate trade-off).

---

## 13. Self-test

```sh
bash test_hide.sh
```

Covers: config hiding, file hiding, redirection, two-path redirection regression, `HIDE_SO`
(maps/smaps/auto-hide), `/proc/mounts`, `statfs`, restricted paths, etc. — 16 assertions.

---

## 14. FAQ

**Q: Why can `ls` no longer see a hidden file, but `mv` can still operate on it?**
A: `HIDE_FILES` filters via hooks, but some programs issue raw system calls (bypassing the libc
wrappers); everyday tools (ls/cat/rm) behave correctly.

**Q: Why do some commands report `Permission denied` or fall back to `/vendor/bin/sh` after
hiding `/system/bin/sh`?**
A: Shell command resolution scans `PATH` with `stat`/`access`; hiding makes `/system/bin/sh`
skipped, so it falls back to another `sh` later in `PATH` (e.g. `/vendor/bin/sh`), and vendor
binaries run in a restricted namespace. It is recommended **not to hide `/system/bin/sh`**; to
change behaviour, put a **visible** wrapper earlier in `PATH`.

**Q: Will `execve` execute a hidden/redirected file?**
A: It executes the literal path — a hidden original file is still executable, and redirection
does not apply to `execve`.

**Q: How do I hide only `hide.so` itself?**
A: No configuration needed. After loading, the `LD_PRELOAD` value is realpath’d and added to
`HIDE_SO` automatically, hiding it from maps/smaps/map_files.

**Q: Why is the configured `echo $HIDE_FILES` empty?**
A: By design: every configured variable is removed in place from the process environment at
construction, so `env/getenv/printenv/echo` cannot see it.
