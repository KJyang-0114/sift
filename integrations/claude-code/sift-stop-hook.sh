#!/usr/bin/env sh
# Claude Code Stop hook: keep the agent working while Sift reports new
# high-risk findings. Copy to .claude/hooks/ and register it as a Stop hook
# (see docs/agents.md).
#
# Exit 2 hands the LLM-formatted report back to Claude as its next instruction.
# Partial scans, missing tools and the second consecutive stop never block, so
# infrastructure problems cannot trap the agent in a loop.

input=$(cat)
case "$input" in
  *'"stop_hook_active":true'* | *'"stop_hook_active": true'*) exit 0 ;;
esac

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
command -v sift >/dev/null 2>&1 || exit 0

set -- --format llm --fail-on "${SIFT_FAIL_ON:-high}" --min-confidence "${SIFT_MIN_CONFIDENCE:-medium}"
if [ -f sift-baseline.json ]; then
  set -- "$@" --baseline sift-baseline.json
fi

report=$(sift scan . "$@" 2>/dev/null)
status=$?
if [ "$status" -eq 1 ]; then
  printf 'Sift found new security issues in this change. Fix them before finishing.\n\n%s\n' "$report" >&2
  exit 2
fi
exit 0
