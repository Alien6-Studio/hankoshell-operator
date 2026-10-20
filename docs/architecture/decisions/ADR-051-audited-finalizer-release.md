# ADR-051: Independently approved administrator finalizer release

Status: Accepted

## Context

Normal cleanup deliberately retains finalizers when ownership, native dependencies
or audit acknowledgement cannot be verified. Removing every finalizer manually
can discard another controller's protection and erase the recovery decision.
Administrators need an explicit exceptional procedure without granting a new
cleanup bypass to the operator. This is separate from the experimental lifecycle
operation approval boundary in [ADR-050](ADR-050-experimental-lifecycle-authority.md).

## Decision

An administrator-only CLI prepares a short-lived plan for one terminating CR and
one allowlisted finalizer. Cluster, namespace, target and admission-guard UIDs,
resourceVersion, generation, deletion timestamp and complete finalizer-list digest
bind the decision. A distinct authenticated human approver accepts orphaned
provider state and Kubernetes garbage collection. The operator has no recovery
role or record-writing authority.

Native Kubernetes admission protects immutable request, approval, intent and
observation ConfigMaps in a dedicated namespace. The CLI checks the exact guard
specification, its identity and a real dry-run provenance denial. A durable,
acknowledged intent precedes one JSON Patch with UID/version/list preconditions.
An existing intent prevents patch replay. A separate observation can report
absence/presence or replacement, including after expiry, without asserting native
cleanup or causality. No provider client, Secret endpoint or Kubernetes deletion
operation is exposed by the CLI.

## Consequences

The process adds explicit two-person review and retained decision evidence while
preserving unrelated finalizers. It depends on trusted administrator kubeconfigs,
clock synchronization and a deployment maintenance freeze. Quiescence is checked
before each release; it is not an atomic lock against privileged rescaling.

Executor RBAC includes general patch authority within explicitly selected target
namespaces. Admission protects the records, not every administrator command.
Cluster administrators can retire the guard or delete the audit namespace;
external audit retention remains their responsibility. ConfigMaps are not a
tamper-proof archive. Approval expires rather than granting standing authority;
group revocation does not retrospectively cancel an already recorded decision.

API qualification exercises authenticated CLI use and adversarial admission on
the supported Kubernetes matrix. Provider cleanup, node garbage collection,
external audit recovery and connected production operation remain unqualified.

## Enforcement

- [Normal Role cleanup and finalizer ownership](../../../internal/controller/hankorole_controller.go)
- [CLI state machine](../../../tools/operations/finalizer_recovery.py)
- [Failure and concurrency fixtures](../../../tests/tooling/test_finalizer_recovery.py)
- [Admission policy](../../../config/recovery/approval-policy.yaml)
- [Independent administrator audit access](../../../config/recovery/audit-access.yaml)
- [Target namespace access](../../../config/recovery/target-access.yaml)
- [Authenticated API and CLI regression](../../../api/v1alpha1/finalizer_recovery_integration_test.go)
- [Actual CLI fixture](../../../tools/qualification/fixtures/finalizer_recovery_fixture.py)
- [Operational procedure](../../finalizer-recovery.md)
