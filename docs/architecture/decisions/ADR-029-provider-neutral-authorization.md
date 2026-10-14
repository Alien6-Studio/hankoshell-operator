# ADR-029: Typed provider authorization with explicit capabilities

Status: Accepted

## Context

Provider authorization models do not have interchangeable semantics. Exposing raw
provider policy JSON or silently dropping unsupported resources or principals
would bypass portable meaning, local ownership and security checks.

## Decision

Use a typed HankoResourceServer aggregate for scopes, resources and allow-only
permissions. Domain drivers expose capabilities explicitly and adapt provider
clients. Reconcilers resolve Kubernetes references and authority; unsupported or
lossy desired semantics fail before mutation. No arbitrary provider JSON becomes
an executable portable plan.

The local compiler seals intent, resolved identities and capability requirements.
Execution rechecks freshness and ownership and records applied evidence only
after acceptable read-back. Observe is read-only; a matching provider name or
status ID does not implicitly acquire ownership. Domain drivers remain separate;
the common IAM contract supplies identities, classifications and preconditions,
not a universal interface with every provider operation.

## Consequences

Capability gaps are reviewable and fail closed. The supported portable surface
cannot express every native policy. Keycloak is the current production adapter;
this decision does not claim a second provider, semantic parity or a general
migration engine. Internal plan hashes are neither signatures nor authorization
credentials, and multi-call reconciliation is not an atomic provider transaction.
In-process plans do not preselect the future signed fleet transport protocol.

## Enforcement

- [Driver and capability model](../../../internal/authorization/driver.go),
  [capability tests](../../../internal/authorization/driver_test.go),
  [compiler](../../../internal/authorization/plan.go) and
  [identity and precondition tests](../../../internal/authorization/plan_test.go).
- [Resource-server reconciler](../../../internal/controller/hankoresourceserver_controller.go)
  and [ownership/reconciliation tests](../../../internal/controller/hankoresourceserver_controller_test.go).
- [Import rules](../../../.go-arch-lint.yml),
  [IAM engine contract](../iam-contract-engine.md) and
  [portable/native boundaries](../provider-boundaries.md).
