#!/usr/bin/env bash
# hide.so 自测：构建后用一组用例验证隐藏/放行/重定向/脱敏/跳过注入等。
set -u
D="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
cp "$D/hide.c" "$T/hide.c"
clang -shared -fPIC -O2 -o "$T/hide.so" "$T/hide.c" || { echo "build failed"; exit 1; }
cd "$T"
: > secret; printf 'R1\n' > r1; printf 'R2\n' > r2
mkdir rr
if [ -x /system/bin/sh ]; then cp /system/bin/sh rr/probe; else cp /bin/sh rr/probe; fi
chmod +x rr/probe

# 小型可执行程序：exec/重定向用例使用二进制而非脚本（脚本解释器还需要 open 读取脚本）
cat > mkexec.c <<'EOF'
#include <stdio.h>
int main(void) { puts("PLACEHOLDER"); return 0; }
EOF
for n in hidprog allowprog redirprog; do
  case $n in
    hidprog)   txt=RUNOK ;;
    allowprog) txt=ALLOWOK ;;
    redirprog) txt=REDIROK ;;
  esac
  sed "s/PLACEHOLDER/$txt/" mkexec.c > "$n.c"
  clang -O2 -o "$n" "$n.c" 2>/dev/null || { echo "$n build failed"; exit 1; }
done

# fstatat/faccessat 探测助手：输出两个调用的返回值（0=成功）
cat > probe.c <<'EOF'
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int c, char **v) {
    (void)c;
    struct stat st;
    int a = faccessat(AT_FDCWD, v[1], F_OK, 0);
    int b = fstatat(AT_FDCWD, v[1], &st, 0);
    printf("%d%d\n", a, b);
    return 0;
}
EOF
clang -O2 -o probe probe.c 2>/dev/null || { echo "probe build failed"; exit 1; }

pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $1 (got [$2] want [$3])"; fi; }
run() { env LD_PRELOAD=./hide.so "$@"; }

# 配置变量隐藏
ck "HIDE_FILES shell-var+getenv" "$(run HIDE_FILES="$T/secret" bash -c 'echo "[$HIDE_FILES]"; printenv HIDE_FILES')" "[]"
ck "HIDE_FILES absent env"       "$(run HIDE_FILES="$T/secret" bash -c 'env | grep -c "^HIDE_FILES=" || true')" "0"
ck "HIDE_FILES absent environ"   "$(run HIDE_FILES="$T/secret" bash -c 'tr "\0" "\n" < /proc/self/environ | grep -c "^HIDE_FILES=" || true')" "0"
ck "ALLOW_ACCESS absent env"     "$(run ALLOW_ACCESS="$T/secret" bash -c 'env | grep -c "^ALLOW_ACCESS=" || true')" "0"
ck "SKIP_RESTRICTED_PATHS absent env" "$(run SKIP_RESTRICTED_PATHS=/vendor bash -c 'env | grep -c "^SKIP_RESTRICTED_PATHS=" || true')" "0"
ck "HIDE_SO absent env"          "$(run HIDE_SO=hide.so bash -c 'env | grep -c "^HIDE_SO=" || true')" "0"
ck "HIDE_MOUNT absent env"       "$(run HIDE_MOUNT=/data bash -c 'env | grep -c "^HIDE_MOUNT=" || true')" "0"

# 隐藏（仅绝对路径；目录/文件都按绝对路径匹配）
ck "HIDE_FILES hide readdir" "$(run HIDE_FILES="$T/secret" bash -c 'ls | grep -c "^secret$" || true')" "0"
ck "HIDE_FILES stat ENOENT"  "$(run HIDE_FILES="$T/secret" bash -c 'test -e secret && echo yes || echo no')" "no"
ck "HIDE_FILES open ENOENT"  "$(run HIDE_FILES="$T/secret" bash -c 'cat secret 2>/dev/null | wc -c')" "0"
ck "HIDE_FILES relative ignored" "$(run HIDE_FILES=secret bash -c 'test -e secret && echo yes || echo no' 2>/dev/null)" "yes"
ck "HIDE_FILES execve ENOENT" "$(run HIDE_FILES="$T/hidprog" bash -c '"$0" >/dev/null 2>&1; echo $?' "$T/hidprog")" "127"

# ALLOW_ACCESS：fstatat/faccessat 探测与 execve 放行；其余钩子不受影响
ck "ALLOW faccessat/fstatat" "$(run HIDE_FILES="$T/secret" ALLOW_ACCESS="$T/secret" ./probe secret)" "00"
ck "no ALLOW fstatat ENOENT" "$(run HIDE_FILES="$T/secret" ./probe secret)" "-1-1"
ck "ALLOW_ACCESS execve"     "$(run HIDE_FILES="$T/allowprog" ALLOW_ACCESS="$T/allowprog" bash -c '"$0" 2>/dev/null' "$T/allowprog")" "ALLOWOK"

# 重定向（含隐藏目标可达、execve 重定向）
ck "REDIRECT read" "$(run REDIRECT_FILES="$T/r1=$T/r2" bash -c 'cat r1')" "R2"
ck "REDIRECT hidden dst reachable"  "$(run HIDE_FILES="$T/r2" REDIRECT_FILES="$T/r1=$T/r2" bash -c 'cat r1')" "R2"
ck "REDIRECT direct dst still hidden" "$(run HIDE_FILES="$T/r2" REDIRECT_FILES="$T/r1=$T/r2" bash -c 'cat r2 2>/dev/null | wc -c')" "0"
ck "REDIRECT execve" "$(run REDIRECT_FILES="$T/alias=$T/redirprog" bash -c '"$0" 2>/dev/null' "$T/alias")" "REDIROK"

# HIDE_SO
ck "HIDE_SO maps"  "$(run HIDE_SO=hide.so bash -c 'grep -c hide.so /proc/self/maps || true')" "0"
ck "HIDE_SO smaps" "$(run HIDE_SO=hide.so bash -c 'grep -c hide.so /proc/self/smaps || true')" "0"
# 自动隐藏 LD_PRELOAD 自身（未设 HIDE_SO）
ck "auto-hide LD_PRELOAD maps" "$(run bash -c 'grep -c hide.so /proc/self/maps || true')" "0"
ck "auto-hide LD_PRELOAD map_files" "$(run bash -c 'ls -l /proc/self/map_files 2>/dev/null | grep -c "hide.so" || true')" "0"

# HIDE_MOUNT
ck "HIDE_MOUNT /proc/mounts" "$(run HIDE_MOUNT=/data bash -c 'awk "\$2==\"/data\"" /proc/mounts | wc -l')" "0"
ck "HIDE_MOUNT statfs"       "$(run HIDE_MOUNT=/data bash -c 'stat -f /data >/dev/null 2>&1 && echo ok || echo blocked')" "blocked"

# SKIP_RESTRICTED_PATHS：该目标不注入 hide.so，故 secret 可见
ck "SKIP_RESTRICTED_PATHS" "$(run SKIP_RESTRICTED_PATHS="$T/rr" HIDE_FILES="$T/secret" bash -c './rr/probe -c "ls"' | grep -c "^secret$" || true)" "1"

# 双路径重定向：rename(A,C) 且 A->B、C->D，应把 B 改名为 D（回归 REDIR 缓冲覆盖 bug）
printf 'B-content\n' > B; printf 'D-content\n' > D
printf '#include <stdio.h>\nint main(int c,char**v){(void)c;return rename(v[1],v[2]);}\n' > rn.c
clang -O2 -o rn rn.c 2>/dev/null
run REDIRECT_FILES="$T/A=$T/B:$T/C=$T/D" ./rn A C
ck "REDIRECT two-path rename" "$(cat D 2>/dev/null)" "B-content"

echo "PASS=$pass FAIL=$fail"
[ "$fail" = 0 ]
