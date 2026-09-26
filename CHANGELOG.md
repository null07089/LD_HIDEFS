# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
