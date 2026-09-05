# Sift Maintainer Handoff

Last updated: 2026-09-05

This document records the maintainer-approved decisions needed to continue the v0.2 hardening work. It is a project handoff, not a transcript: it intentionally excludes credentials, personal data, and private conversation.

## Current status

| Stage | Work | Status |
| --- | --- | --- |
| A1 | Test and CI foundation | Merged in [PR #1](https://github.com/KJyang-0114/sift/pull/1) |
| A2 | Core contracts and Finding v2 | Ready for maintainer review in [PR #2](https://github.com/KJyang-0114/sift/pull/2); do not merge without explicit approval |
| A3 | Secure target resolver | Next after A2 is approved and merged |

The target releases are `v0.2.0-alpha.1` after Stage A and `v0.2.0` after Stage B.

## Maintainer-approved product decisions

- Linux and macOS receive the complete supported feature set. Windows remains analysis-only and must never execute generated code.
- Dynamic execution is disabled by default and requires an explicit opt-in such as `--enable-execution`.
- Generated code may execute only through an approved Docker or Podman container backend. Direct host execution must be removed.
- LLM features are offline by default. Cloud LLM use requires the user's own provider/API key and explicit acknowledgement that selected source code will be sent to and processed by that provider.
- The product must clearly warn users that submitted data may be processed or used according to the model provider's terms. `--no-upload` overrides configuration.
- API keys are environment-first. Persist a key locally only when the user explicitly requests it, use restricted permissions, and never store it in scan history.
- Stage B is accuracy-first. Only evidence-backed, high-confidence findings may block a pull request.
- Breaking changes are allowed during this hardening effort, but user-visible migrations must be documented in `MIGRATION.md`.

## Security and privacy invariants

- Never upload source or execute generated code by default.
- Never run generated code directly on the host.
- Do not expose API keys, Git credentials, host environment variables, absolute local paths, or writable repository mounts to generated code.
- Container execution defaults: network disabled, read-only root filesystem, non-root user, fresh temporary workspace, and bounded CPU, memory, process count, duration, and output.
- Expected analyzer, integration, or network failures become typed diagnostics; they must not be fabricated as security findings.
- Pass paths and command arguments as structured slices, never as shell-joined strings.

## Pull request workflow

Each substantial batch is isolated in its own branch and pull request:

1. Write tests first where behavior changes.
2. Keep the PR scoped to one roadmap batch and document compatibility or rollback concerns.
3. Open as Draft, then verify formatting, module integrity, vet, unit tests, race tests, native platform builds, and the repository security scan.
4. Mark Ready only after all required checks pass.
5. Request maintainer review. Never merge without explicit maintainer authorization.

## Roadmap order

### Stage A — secure foundation

1. Test and CI foundation — complete and merged.
2. Core interfaces and Finding v2 — implemented in PR #2.
3. Secure target resolver.
4. Privacy controls, API-key handling, and upload consent.
5. External command runner and isolated generated-code execution.
6. Release and open-source security gates; publish `v0.2.0-alpha.1`.

### Stage B — accuracy and release quality

7. Evidence normalization, deduplication, suppression, and baselines.
8. Semgrep fixtures and dependency-verifier accuracy.
9. Privacy-safe LLM analyzer and evaluation harness.
10. Diff/cache correctness, performance, migration polish, and `v0.2.0` release.

## Next batch: A3 secure target resolver

A3 should be a separate PR after A2 is merged. Its acceptance criteria are:

- Resolve and retain one canonical repository root.
- Canonicalize every candidate path and verify symlink containment within that root.
- Fail closed for invalid, ambiguous, or escaping paths.
- Parse Git diff paths using NUL-delimited output.
- Transport paths as structured slices throughout the scan pipeline.
- Centralize ignore rules, supported extensions, maximum file size, and maximum file count.
- Report unreadable individual files as typed diagnostics without silently widening scope.
- Add adversarial tests for traversal, symlink escape, unusual filenames, oversized input, and limit enforcement.

## Planned exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan completed and no configured finding threshold was reached |
| 1 | Finding policy threshold reached |
| 2 | Invalid configuration or target |
| 3 | Partial scan caused by analyzer or integration failure |
| 4 | Internal failure |

## Source documents

- [v0.2 hardening design](superpowers/specs/2026-08-16-sift-v0.2-hardening-design.md)
- [A1 test and CI plan](superpowers/plans/2026-08-16-a1-testing-ci-foundation.md)
- [A2 core contracts and Finding v2 plan](superpowers/plans/2026-08-17-a2-core-contracts-finding-v2.md)
- [Migration guide](../MIGRATION.md)
- [Finding v2 JSON Schema](schemas/finding-v2.schema.json)
