# ADR-017: Image policy before operator workload submission

Status: Accepted

## Context

Theme builder and managed Keycloak image fields can cause execution with PVC or
credential access. Permission to submit a CR must not by itself authorize arbitrary
container code in the operator's namespace.

## Decision

Image policy is a dedicated standalone package, checked before the operator submits
the relevant workload. Missing or invalid trust configuration denies authorization.
Cluster admission can add protection, but is not a substitute for local checks.

The original registry allowlist remains an identity check.
[ADR-044](ADR-044-structural-image-trust.md) replaces historical string-prefix
matching with structural OCI identity matching. Signature verification, initially
deferred, is now required at execution by
[ADR-047](ADR-047-signed-workload-approvals.md). `ValidateImageRef` alone never
authorizes a managed workload or operator replacement.

## Consequences

CR authors cannot choose a trusted publisher or bypass local policy merely by
using a plausible registry hostname. Administrators must provision independently
controlled image approvals and keep required cleanup images approved. Missing
trust can block new workloads and cleanup; approval failure does not remove
existing running pods. This is the operator submission boundary, not a claim of
cluster-wide policy enforcement for workloads created by other identities.

## Enforcement

- [Image policy package](../../../internal/imagevalidator/validator.go) and
  [deny-all and identity tests](../../../internal/imagevalidator/validator_test.go).
- [Execution approval](../../../internal/imagevalidator/approval.go) and
  [approval tests](../../../internal/imagevalidator/approval_test.go).
- [Standalone package boundary](../../../.go-arch-lint.yml).
- [Installation and trust configuration](../../secure-deployment.md).
