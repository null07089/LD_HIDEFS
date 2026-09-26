#!/data/data/com.termux/files/usr/bin/bash
# hide.so 自测：构建后用一组用例验证隐藏/重定向/脱敏/受限前缀等。
set -u
D="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
cp "$D/hide.c" "$T/hide.c"
clang -shared -fPIC -O2 -o "$T/hide.so" "$T/hide.c" || { echo "build failed"; exit 1; }
cd "$T"
: > secret; printf 'R1\n' > r1; printf 'R2\n' > r2
mkdir rr; cp /system/bin/sh rr/probe 2>/dev/null

pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $1 (got [$2] want [$3])"; fi; }
run() { env LD_PRELOAD=./hide.so "$@"; }

# 配置变量隐藏
ck "HIDE_FILES shell-var+getenv" "$(run HIDE_FILES=secret bash -c 'echo "[$HIDE_FILES]"; printenv HIDE_FILES')" "[]"
ck "HIDE_FILES absent env"      "$(run HIDE_FILES=secret bash -c 'env | grep -c "^HIDE_FILES=" || true')" "0"
ck "HIDE_FILES absent environ"  "$(run HIDE_FILES=secret bash -c 'tr "\0" "\n" < /proc/self/environ | grep -c "^HIDE_FILES=" || true')" "0"
ck "HIDE_SO absent env"         "$(run HIDE_SO=hide.so bash -c 'env | grep -c "^HIDE_SO=" || true')" "0"
ck "HIDE_MOUNT absent env"      "$(run HIDE_MOUNT=/data bash -c 'env | grep -c "^HIDE_MOUNT=" || true')" "0"

# 隐藏
ck "HIDE_FILES hide readdir" "$(run HIDE_FILES=secret bash -c 'ls | grep -c "^secret$" || true')" "0"
ck "HIDE_FILES stat ENOENT"  "$(run HIDE_FILES=secret bash -c 'test -e secret && echo yes || echo no')" "no"

# 重定向
ck "REDIRECT read" "$(run REDIRECT_FILES="$T/r1=$T/r2" bash -c 'cat r1')" "R2"

# HIDE_SO
ck "HIDE_SO maps"  "$(run HIDE_SO=hide.so bash -c 'grep -c hide.so /proc/self/maps || true')" "0"
ck "HIDE_SO smaps" "$(run HIDE_SO=hide.so bash -c 'grep -c hide.so /proc/self/smaps || true')" "0"
# 自动隐藏 LD_PRELOAD 自身（未设 HIDE_SO）
ck "auto-hide LD_PRELOAD maps" "$(run bash -c 'grep -c hide.so /proc/self/maps || true')" "0"
ck "auto-hide LD_PRELOAD map_files" "$(run bash -c 'ls -l /proc/self/map_files 2>/dev/null | grep -c "hide.so" || true')" "0"

# HIDE_MOUNT
ck "HIDE_MOUNT /proc/mounts" "$(run HIDE_MOUNT=/data bash -c 'awk "\$2==\"/data\"" /proc/mounts | wc -l')" "0"
ck "HIDE_MOUNT statfs"       "$(run HIDE_MOUNT=/data bash -c 'stat -f /data >/dev/null 2>&1 && echo ok || echo blocked')" "blocked"

# 受限前缀：该目标不注入 hide.so，故 secret 可见
ck "HIDE_RESTRICTED_PATHS" "$(run HIDE_RESTRICTED_PATHS="$T/rr" HIDE_FILES=secret bash -c './rr/probe -c "ls" | grep -c "^secret$" || true')" "1"

# 双路径重定向：rename(A,C) 且 A->B、C->D，应把 B 改名为 D（回归 REDIR 缓冲覆盖 bug）
printf 'B-content\n' > B; printf 'D-content\n' > D
printf '#include <stdio.h>\nint main(int c,char**v){(void)c;return rename(v[1],v[2]);}\n' > rn.c
clang -O2 -o rn rn.c 2>/dev/null
run REDIRECT_FILES="$T/A=$T/B:$T/C=$T/D" ./rn A C
ck "REDIRECT two-path rename" "$(cat D 2>/dev/null)" "B-content"

echo "PASS=$pass FAIL=$fail"
[ "$fail" = 0 ]
