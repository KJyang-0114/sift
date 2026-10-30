#!/usr/bin/env sh
# Behavior tests for sift-stop-hook.sh using a fake sift binary.
set -u
here=$(cd "$(dirname "$0")" && pwd)
hook="$here/sift-stop-hook.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/project"
cat > "$work/bin/sift" <<'FAKE'
#!/usr/bin/env sh
printf '%s\n' "$*" > "$FAKE_ARGS"
echo "# Code Issues Report"
exit "$FAKE_EXIT"
FAKE
chmod +x "$work/bin/sift"
failures=0

check() { # name, stdin, fake exit, expected hook exit, [expected stderr substring]
  FAKE_EXIT=$3 FAKE_ARGS="$work/args" CLAUDE_PROJECT_DIR="$work/project" PATH="$work/bin:/usr/bin:/bin" \
    sh "$hook" <<IN 2>"$work/err"
$2
IN
  got=$?
  if [ "$got" -ne "$4" ] || { [ -n "${5:-}" ] && ! grep -qF "$5" "$work/err"; }; then
    echo "FAIL $1: exit=$got want=$4 stderr=$(cat "$work/err")"
    failures=$((failures + 1))
  else
    echo "ok   $1"
  fi
}

check "new findings block" '{"stop_hook_active":false}' 1 2 "Fix them before finishing"
check "clean scan allows stop" '{"stop_hook_active":false}' 0 0
check "partial scan allows stop" '{"stop_hook_active":false}' 3 0
check "second stop allows stop" '{"stop_hook_active": true}' 1 0
grep -qF -- "--fail-on high --min-confidence medium" "$work/args" || { echo "FAIL default thresholds: $(cat "$work/args")"; failures=$((failures + 1)); }
touch "$work/project/sift-baseline.json"
check "baseline is used" '{"stop_hook_active":false}' 0 0
grep -qF -- "--baseline sift-baseline.json" "$work/args" || { echo "FAIL baseline flag: $(cat "$work/args")"; failures=$((failures + 1)); }
if FAKE_EXIT=1 CLAUDE_PROJECT_DIR="$work/project" PATH="/usr/bin:/bin" sh "$hook" </dev/null 2>/dev/null; then
  echo "ok   missing sift allows stop"
else
  echo "FAIL missing sift"
  failures=$((failures + 1))
fi

exit "$failures"
