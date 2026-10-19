# ADR-009: Declarative Kubernetes reconciliation and dependency boundaries

Status: Accepted

## Context

Provider writes, credential lifecycle and drift reconciliation need one owner
within the hankoShell integration. Independent API-side mutations would compete
with the desired state stored in Kubernetes. The extracted operator must remain
usable without importing the platform API or Hub implementation.

## Decision

The operator reconciles namespaced CR specifications into provider state and
publishes observations in status. Controllers resolve references and authority;
provider clients and domain adapters perform provider calls. Desired state and
status do not carry credential values: canonical credentials belong in Kubernetes
Secrets, with separately authorized projections. Observe/import does not acquire
write authority or implicitly adopt an existing provider object.

The command package wires components. Controllers may use the explicitly listed
domain, transport and integration packages. API types have no runtime project
dependencies; lower-level packages cannot import reconcilers. The checked import
graph is authoritative as packages evolve. Provider-neutral domain execution is
refined by [ADR-029](ADR-029-provider-neutral-authorization.md); optional external
distribution is described by [ADR-010](ADR-010-hub-pull-distribution.md).

## Consequences

Reconciliation is eventually consistent and exposes partial failures. Kubernetes
and provider changes are not an atomic transaction. Ownership/freshness checks and
recovery journals are necessary before retries and deletion. External provider
administrators remain privileged; the import graph cannot prevent their writes.
Lifecycle APIs remain experimental where installed workflows are unqualified.
The platform API's own enforcement lives outside this repository; this record
does not claim to validate that service or to provide another production provider.

## Enforcement

- [Import boundaries](../../../.go-arch-lint.yml), checked by `make arch`.
- [Application reconciler](../../../internal/controller/hankoapplication_controller.go)
  and [controller tests](../../../internal/controller/hankoapplication_controller_test.go).
- [Ownership and adoption contract](../existing-keycloak-adoption.md).
- [Current provider boundaries](../provider-boundaries.md).
