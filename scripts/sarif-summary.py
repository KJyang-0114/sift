#!/usr/bin/env python3
"""Summarize a Sift SARIF report as Markdown for a GitHub job summary.

Usage: sarif-summary.py REPORT.sarif EXIT_CODE [GITHUB_OUTPUT]
When GITHUB_OUTPUT is given, also writes active= and suppressed= counts to it.
"""
import collections
import json
import sys


def main():
    report_path, exit_code = sys.argv[1], sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else None
    # Both paths are written by this action's own steps, not taken from scanned code.
    with open(report_path, encoding="utf-8") as handle:  # nosemgrep: sift.path-traversal-file-op
        run = json.load(handle)["runs"][0]
    results = run.get("results", [])
    active = [r for r in results if not r.get("suppressions")]
    suppressed = len(results) - len(active)
    levels = collections.Counter(r.get("level", "warning") for r in active)
    rules = collections.Counter(r.get("ruleId", "?") for r in active)
    invocation = (run.get("invocations") or [{}])[0]
    complete = invocation.get("executionSuccessful", True)

    print("## Sift scan")
    print(f"- Status: {'complete' if complete else 'partial'} (exit {exit_code})")
    counts = ", ".join(f"{level}={count}" for level, count in sorted(levels.items()))
    print(f"- New findings: {len(active)}" + (f" ({counts})" if counts else ""))
    if suppressed:
        print(f"- Accepted by baseline: {suppressed}")
    if rules:
        print("\n| Rule | Count |\n|---|---|")
        for rule, count in rules.most_common(10):
            print(f"| `{rule}` | {count} |")
    notes = invocation.get("toolExecutionNotifications", [])
    if notes:
        print("\n### Diagnostics")
        for note in notes[:10]:
            print(f"- {note.get('level', 'note')}: {note.get('message', {}).get('text', '')}")

    if output_path:
        with open(output_path, "a", encoding="utf-8") as handle:  # nosemgrep: sift.path-traversal-file-op
            handle.write(f"active={len(active)}\nsuppressed={suppressed}\n")


if __name__ == "__main__":
    main()
