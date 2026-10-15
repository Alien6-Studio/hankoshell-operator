# ADR-048: Full qualification matrix on pull requests

Status: Accepted

## Context

RFC #113 asked
whether pull requests may run a reduced qualification matrix while `main`, the
weekly schedule and the release path keep the full one. Measured evidence from the
`ci.yml` workflow history (2026-10-07 to 2026-10-15, 207 runs): 147 pull-request
runs — 68 success, 47 cancelled, 32 failure; a green run takes a median 12-minute
wall clock (p90 43 minutes, bounded by the installed-workload cell on the newest
Kubernetes) and consumes about 293–298 runner-minutes across 24 jobs. The
repository is public, so GitHub-hosted standard runners are free; the cost of the
matrix is wall clock, not money.

Detection value over the same window, counting the jobs that failed on the 32 red
pull-request runs (excluding the aggregate `Source and chart checks` gate, which
fails derivatively, and 16 dependabot runs in which no qualification job started):
installed operator system test 8 runs; installed workload on Kubernetes 1.37.0
8 runs (both Keycloak versions); source checks 3; Keycloak 26.7.5 Admin API 1.
The older Kubernetes cells (1.35.0, 1.36.2) failed only in a single systemic run
in which every workload cell failed at once. A reduced set of newest Kubernetes ×
both Keycloak versions would have caught every regression in this one-week window.

## Decision

Pull requests keep the full qualification matrix. The reduced-matrix candidate is
refused, and the detection risk it would accept is refused with it:

- The required `Source and chart checks` gate must represent the full matrix
  before merge. With protected squash merges there is no separate merge-candidate
  run, so a reduced pull-request matrix converts merge-time detection into a red
  `main` after merge — the failure mode the scheduled-failure and flaky tracking
  issues exist to eliminate, not to absorb. A future reduction is only acceptable
  together with a full-matrix run on the merge candidate (merge queue).
- The measured window is one week. It shows the older Kubernetes cells rarely
  detect uniquely, not that they never do; the single systemic failure confirms
  the cells share failure modes only most of the time.
- The repository is public, so the matrix costs no runner money, and the wall
  clock is bounded by the longest single cell regardless of matrix width.

The optimizations retained instead of shrinking the matrix:

- Superseded-push cancellation (`concurrency` with `cancel-in-progress`),
  measured: 47 of 147 pull-request runs (32%) were stopped early by a newer push.
- Fast source preflight gating every expensive job, measured under 4 minutes, so
  obviously broken pushes never start the matrix.
- Keycloak qualification sharded into core/adoption/protocols jobs per version,
  each with its own Keycloak container (`scripts/keycloak-shards.json`), splitting
  the measured 1,047-second serial integration package; the per-shard CI
  measurement lands with the first full run of that change set.
- Per-test outcome artifacts with the weekly flaky report and tracking issue, so
  flaky tests are fixed instead of paid for by rerunning the whole matrix.

## Consequences

Every pull-request push continues to cost the full matrix wall clock, including
dependabot and documentation-only changes; preflight bounds that cost for broken
pushes. Merge-time qualification depth stays identical to `main`, the schedule and
the release path, so the ruleset keeps a single meaning for the required gate.
Revisit this decision if the repository becomes private, if the matrix outgrows
the current 24 jobs, or if a quarter of flaky-report history shows cells that
never detect uniquely — and then only together with a merge-queue full run.

## Enforcement

- [Qualification matrix and required gate](../../../.github/workflows/ci.yml):
  `preflight` blocks every expensive job and `checks` requires all of them.
- The qualified surface the matrix exercises on every pull request, for example
  [adoption reconciliation](../../../internal/controller/adoption_apply.go) and
  the [real-Keycloak characterization tests](../../../internal/controller/keycloak_adoption_characterization_test.go)
  sharded by `scripts/keycloak-shards.json`.
- [Contract tests](../../../scripts/test_release_contract.py): preflight gating,
  gate completeness and scoped write permissions.
- [Weekly outcome history](../../../.github/workflows/test-history.yml) with the
  [flaky report](../../../scripts/flaky-report.py) and
  [tracking issue](../../../scripts/flaky-issue.py).
