# ADR-044: Structural OCI registry and repository identity

Status: Accepted

## Context

String-prefix registry checks accept lookalike hosts and repositories, such as
`registry.example.attacker.invalid` or `quay.io/keycloak-attacker`. The allowlist
introduced by [ADR-017](ADR-017-image-supply-chain.md) needs a structural identity
comparison rather than string-prefix trust.

## Decision

Parse canonical, explicitly qualified OCI references with the distribution
reference package. Match the complete registry including its port, then the exact
repository or a child separated by `/`. Registry-only entries cover repositories
in that registry. Trim surrounding allowlist whitespace and a trailing slash for
configuration compatibility; do not normalize image input into a trusted identity.

Reject malformed/implicit references. Allowlist entries contain no tag, digest,
scheme, credentials or wildcard. Empty configuration denies all references; one
invalid entry makes the entire validator deny all. Registry comparisons are exact.

## Consequences

Correct existing canonical entries continue to work; administrators must fix
malformed configuration rather than rely on permissive fallback. Structural
validation can accept a tag, but proves only its registry/repository identity.
Current workload submission additionally requires the immutable digest approval
and signature defined by [ADR-047](ADR-047-signed-workload-approvals.md). Returning
to string-prefix checks would restore the spoofing weakness and is not a safe
configuration rollback.

## Enforcement

- [Parser and complete-boundary matching](../../../internal/imagevalidator/validator.go).
- [Lookalike, malformed allowlist and Docker Hub normalization tests](../../../internal/imagevalidator/validator_test.go).
- [Pinned parser dependency](../../../go.mod).
- [Execution approval boundary](../../../internal/imagevalidator/approval.go).
