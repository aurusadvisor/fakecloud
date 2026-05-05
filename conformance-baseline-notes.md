# Conformance baseline notes

`conformance-baseline.json` is the floor a PR must clear in CI. Numbers are
deliberately set below the latest observed pass count to absorb cross-run
flake; raising them too aggressively turns unrelated PRs red on transient
failures that aren't reproducible locally.

## Wide-margin services

A few services carry an unusually large gap between baseline and actual
pass count because the conformance harness shows non-deterministic results
across CI runs:

- **cognito-idp** — observed 4416 / 4426 / 4434 / 4479 across 4 consecutive
  runs of unchanged code. Baseline kept well below the floor.
- **kms** — observed 2017 / 2024 / 2050 / ~2030 across the same window.
  Baseline reduced to 2000 in 2026-04 to absorb the variance.

## TODO: harness state isolation

The flake almost certainly comes from cross-test state leakage in the
conformance harness rather than real fakecloud regressions: the baseline
drops happened on PRs that touched neither service. The right long-term
fix is harness-side test isolation (per-test fakecloud restart, or
per-test account scoping) rather than continually lowering the baseline.

Tracking under "improve conformance harness isolation" — not yet
scheduled because the harness sits in a separate fork and the fakecloud
side has higher-leverage work first.
