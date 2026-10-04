# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ALLOW_ACCESS`: allow-list of absolute paths exempted from `HIDE_FILES` for
  `fstatat`/`fstatat64`/`faccessat` probes and `execve`; directory entries cover the whole subtree.
- Interposition of the extended-attribute family (`getxattr`, `lgetxattr`, `listxattr`,
  `llistxattr`, `setxattr`, `lsetxattr`, `removexattr`, `lremovexattr`), so extended attributes
  (including the SELinux label `security.selinux`) follow `REDIRECT_FILES`.
- `umount`/`umount2` return `EINVAL` for mount points hidden by `HIDE_MOUNT`.
- Central `cfg_vars` table reused for parsing, `getenv` redaction, `/proc/<pid>/environ`
  sanitization and execve re-injection.
- Configuration is read at construction by scanning `environ` directly (`raw_getenv`), with no
  dependency on `dlsym(getenv)`.
- Buffered (64 KiB) writes for `/proc` text filtering; single-segment cap (`PROC_MAX_SEG`, 8 MiB)
  with fail-closed behaviour.
- Directory-map FIFO eviction (oldest entry dropped) instead of refusing new directories.
- `test_hide.sh` coverage for the new semantics (27 assertions).

### Changed

- **Breaking:** `HIDE_FILES` now accepts **absolute paths only**; bare names and relative paths are
  ignored with a warning on stderr.
- **Breaking:** `execve` now participates in `REDIRECT_FILES`, and files matching `HIDE_FILES` are
  no longer executable (`ENOENT`) unless listed in `ALLOW_ACCESS`.
- Redirection takes precedence over hiding for the operation: a redirect target is reachable through
  `src` even if it is itself hidden; direct access to the target remains hidden.
- **Breaking:** `HIDE_RESTRICTED_PATHS` was renamed to `SKIP_RESTRICTED_PATHS`; the old name is
  neither parsed nor hidden.
- Redirection resolves relative paths with proper `dirfd` semantics (via `/proc/self/fd`).
- Execve environment rebuilding now fails closed with `ENOMEM` instead of leaking unsanitized
  configuration when allocation fails.
- `GET_REAL` no longer aborts on a missing optional symbol; hooks degrade to `ENOSYS`.
- Hidden-path ancestor matching is allocation-free and path entries are length-sorted for early
  exit; inode identities moved to a dedicated table.

### Removed

- Bare-name and relative-path `HIDE_FILES` entries.
- `realpath` fallback for `SKIP_RESTRICTED_PATHS` symlink targets; matching now uses the lexical
  absolute path only.

## [1.0.0] - 2026-09-26

### Added

- `HIDE_FILES`: hide files/directories by bare name, relative path, or absolute path,
  including directory prefix matching and inode identity matching across bind-mount aliases.
- `REDIRECT_FILES`: user-space bind-style path redirection for read/stat/open and related
  operations (files exact-match, directories prefix-match); `execve` is exempt.
- `HIDE_SO`: hide matching library paths from `/proc/<pid>/{maps,smaps,smaps_rollup}` and
  `/proc/<pid>/map_files`; the `LD_PRELOAD` library itself is hidden automatically.
- `HIDE_MOUNT`: hide mount entries from `/proc/<pid>/{mounts,mountinfo,mountstat[s]}` and make
  `statfs`/`statvfs` return `ENOENT` for hidden mount points.
- `HIDE_RESTRICTED_PATHS`: never inject `LD_PRELOAD` into restricted linker-namespace binaries
  (`/vendor`, `/odm`, `/product`, `/system_ext`, `/apex`, …).
- Complete self-hiding of all configured variables (in-place environment removal, `getenv`
  redaction, `/proc/<pid>/environ` sanitization, child re-injection, static/restricted stripping).
- Graceful handling of missing optional libc symbols (no `_exit` on `dlsym` failure).
- Streaming `/proc` text filtering into `memfd`; fail-closed if `memfd` is unavailable.
- `GET_REAL` macro to unify hook real-function lazy loading (serialized `dlsym`).
- `test_hide.sh` self-test (16 assertions).

### Fixed

- Critical: path redirection used a single per-thread buffer, so redirecting two paths in one
  call (e.g. `rename`) overwrote the first, and re-entrant hooks (`realpath` → `lstat`) could
  corrupt an in-use buffer. Now each rewrite uses its own stack `alloca` buffer.
- `HIDE_SO` matching failed for absolute-path tokens because the path field in `maps` is preceded
  by whitespace; the left boundary now accepts whitespace.
- `open` did not read `mode` for `O_TMPFILE`.
- `statfs`/`statvfs` lacked a null check for the real function.
- `handle_proc_file` incorrectly replaced `O_PATH` descriptors with a `memfd`.
- `readdir` lacked a null check for the real function.
- `REDIRECT_FILES` config validation warning for malformed `src=dst` entries.
- `init_hidden` no longer aborts on a single allocation failure.

### Security

- Removed all compile-time defaults (no built-in hidden list, no hard-coded `LD_PRELOAD` target).
- Added GPL-3.0 license and dual-use disclaimer.

[1.0.0]: https://github.com/null07089/LD_HIDEFS/releases/tag/v1.0.0
