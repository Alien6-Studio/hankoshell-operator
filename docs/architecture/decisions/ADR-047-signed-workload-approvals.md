# ADR-047: Signed immutable workload and operator-update approvals

Status: Accepted

## Context

Registry identity alone does not prove the publisher or prevent tag replacement.
Theme cleanup, backup Jobs, managed Keycloak and operator replacement can execute
with sensitive access, including when an image originates in previous status or
a remote update request. They need independent local execution authority.

## Decision

Require an exact canonical SHA-256 digest, full source revision and approval for
the purpose: `theme-builder`, `keycloak`, `database-backup` or `operator-update`.
Administrators own the mounted policy and publisher public keys independently of
CR authors and Hub. An operator update also binds the release version; keyless
operator approval pins the exact release workflow certificate identity and issuer.
The structural checks in [ADR-044](ADR-044-structural-image-trust.md) are not an
alternative to execution verification.

At submission, Cosign verifies the digest and signed source-revision annotation.
The subprocess has a 20-second deadline, no ambient application/signing credentials
and only optional separate pull credentials. Verification output is discarded.
There is no success cache: reload approval and public-key fingerprint after
verification so a detected concurrent revocation or replacement denies submission.
Admission-only validation cannot replace the execution-time verification call.

## Consequences

Registry or verification outages can block new workloads and cleanup. Missing
approval preserves existing running workloads but prevents unapproved submissions;
revocation does not terminate existing pods. Keep reviewed cleanup/rollback digests
approved while needed. Policy distribution has kubelet projection latency and
local rechecks do not form a transaction with Kubernetes submission. Trust-root
write access must be controlled independently; a read-only mount alone does not
prevent API writes. Production trust and publication readiness remain subject to
the separate deployment/release qualification contract.

## Enforcement

- [Approval and revocation checks](../../../internal/imagevalidator/approval.go),
  [workload tests](../../../internal/imagevalidator/approval_test.go) and
  [operator identity/version/revocation tests](../../../internal/imagevalidator/operator_approval_test.go).
- [Bounded verifier](../../../internal/imagevalidator/cosign.go) and
  [credential isolation and exact identity tests](../../../internal/imagevalidator/cosign_test.go).
- [Self-update submission](../../../internal/selfupdate/selfupdate.go) and
  [verification and concurrent administrator edit tests](../../../internal/selfupdate/selfupdate_test.go).
- [Administrator trust configuration](../../secure-deployment.md).
