# ADR-009: Full qualification matrix on pull requests

Status: Accepted

## Context

The operator supports several Kubernetes and Keycloak versions. A passing test
on one pair does not establish compatibility on the other supported pairs.
Protected merges need a consistent meaning for the required qualification gate.

## Decision

Pull requests, `main`, scheduled CI and release qualification keep the complete
supported matrix. Documentation-only changes and dependency updates use the same
required gate. A future reduction requires a full-matrix merge-candidate run
before merge, such as a protected merge queue.

Keep costs bounded through implementation choices:

- Run source preflight before expensive jobs.
- Partition native Keycloak tests into reviewed core/adoption/protocol shards,
  while verifying that every compiled test root is covered.
- Cancel superseded automatic runs. Manual qualification waits behind an active
  run on the same ref so a new request does not interrupt an ongoing campaign.
- Publish per-test outcomes and failure summaries. Investigate failures rather
  than automatically replaying tests or ambiguous provider writes.

There is no requirement to accumulate an arbitrary historical run count, and
no separate weekly flaky-report or tracking-issue workflow.

## Consequences

Every integration PR pays the complete matrix latency. Accumulate a coherent
batch and run local checks before pushing. The required gate retains the same
meaning across PRs, `main` and release qualification. Review matrix cost and
regression coverage when the support window or merge strategy changes.

## Enforcement

- [Qualification matrix and required gate](../../../.github/workflows/ci.yml):
  `preflight` blocks every expensive job and `checks` requires all of them.
- The qualified surface the matrix exercises on every pull request, for example
  [adoption reconciliation](../../../internal/controller/adoption_apply.go) and
  the [real-Keycloak characterization tests](../../../internal/controller/keycloak_adoption_characterization_test.go)
  sharded by `tools/qualification/config/keycloak-shards.json`.
- [Release contract](../../../tools/qualification/checks/release_contract.py) validates
  the source, chart, supported-version matrix and qualification inventories.
