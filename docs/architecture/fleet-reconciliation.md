# Signed fleet desired state

This is the operator-side contract for #76/#77 and ADR-049. It does not implement
Hub signing/distribution or qualify enterprise fleet operation. Keycloak retains
all native extensions. #75 remains the provider-portability evidence boundary;
this protocol binds a contract/source identity without inventing second-provider
conformance. #78–#80 own capability rollout, disconnected provider authority and
the installed fleet matrix.

## Threat model and mechanism decision

A compromised Hub bearer token or distribution channel must not forge a plan.
Independent local administrators approve publisher keys and their exact tenant,
cluster, namespace and source scope. A compromised approved signing key can issue
plans within that scope until locally revoked. A Kubernetes administrator able
to replace trust, status or the operator remains in the trust boundary. TLS
authenticates transport; a signature does not replace TLS or local authority.

| Mechanism | Keys, rotation and offline verification | Decision |
| --- | --- | --- |
| Ed25519 detached signature | Local exact public-key IDs and scope; overlap during locally approved rotation; offline Go crypto verification with bounded typed payloads. No verification network or new cryptographic dependency. | Selected: small fixed mechanism, separate publisher and bearer authority. |
| JWS with EdDSA | Standard envelope/header processing and algorithm/key identifiers; can work offline with pinned keys, but introduces a broader header/serialization profile and strict algorithm/critical-header policy. | Not selected: interoperability does not currently justify another JOSE profile for this finite operator protocol. |
| Sigstore bundle | Can bind workload identities and transparency evidence; offline verification needs a complete bundle and independently managed trust material. Release signing already uses a separate qualified verifier. | Not selected for frequent fleet control: release trust and local fleet issuer authority must remain separate; no external identity/log availability becomes a control-plane prerequisite. |

Primary mechanism references: [Ed25519/RFC 8032](https://www.rfc-editor.org/rfc/rfc8032),
[JWS/RFC 7515](https://www.rfc-editor.org/rfc/rfc7515),
[Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/).
The mechanism choice and scope trade-offs are this operator's decision, not
security guarantees supplied by those formats alone.

## Wire format and exact signing input

GET the existing `/api/v1/bundles/latest` route with
`Accept: application/vnd.hanko.fleet-plan+json`. Authentication retains the scoped
Hub bearer and tenant header. Signed fetch is HTTPS-only, refuses redirects and
query/fragment/userinfo endpoints, bounds the body to 1 MiB and never copies remote
response/error bodies into status or errors. The new media type requires an
upstream Hub implementation; an old HMAC response is refused in signed mode.

The envelope has exactly `version`, `payload`, `signature`:

- `version` is `hanko.sh/fleet-envelope/v1alpha1`.
- `payload` is canonical unpadded base64url of exact JSON payload bytes, at most
  768 KiB. `signature` is unpadded base64url of a 64-byte Ed25519 signature.
- Signing input is UTF-8 `hanko.sh/fleet-envelope/v1alpha1`, a zero byte, then the
  decoded payload. Payload identity is SHA-256 of this same input. No JSON
  reserialization or canonicalization occurs during verification. Publishers
  should serialize deterministically; another byte representation at the same
  sequence conflicts even when it looks semantically equivalent.
- Reject unknown fields, duplicate members, case aliases, trailing values,
  invalid base64, excessive nesting and out-of-range integers. No algorithm or
  key URL is supplied by the envelope.

The signed payload binds:

| Field | Meaning and local verification |
| --- | --- |
| issuer, keyID | Exact locally approved publisher entry, with a currently valid public key. Both are inside signed bytes. |
| target.tenantID, clusterID, namespace, tenantName | One exact approved scope tuple and the current local tenant/credential identity. Scope lists are tuples, not independent wildcard sets. |
| target.tenantUID | Current HankoTenant UID; deleting/recreating the same name does not reuse authority. |
| source.repository, revision, digest | Exact locally approved source name, full lowercase 40-hex revision and SHA-256 digest. These are publisher assertions; a signature does not independently prove repository ancestry or artifact provenance. |
| contractVersion | Exact recognized internal IAM contract version. This is not a public API stability or provider-parity claim. |
| sequence | Positive signed int64, monotonically increasing per tenant UID. |
| issuedAt, notBefore, expiresAt | Nonzero RFC3339 times, positive validity at most one hour. Future issuance/start tolerance is 30 seconds; expiry is strict with no extra grace. |
| requirements, mode | Explicit capability requirements and rollout mode. Current execution accepts empty requirements and `all-or-refuse` only; unsupported requests produce no content writes. #78 extends qualified capability handling. |
| rollbackOf | Future reference to previously verified content. Currently refused; retaining a previous identity is not permission to roll back. |
| content | Finite arrays of IAMProfile, Realm, Application, Theme and ServiceAccount declarations, at most 200 objects, each at most 64 KiB. |

Each object explicitly declares its API version, expected kind, name, target
namespace and exact `hanko.sh/tenant` label. Only name/namespace/labels/annotations
are accepted as metadata. Reject status, finalizers, ownerReferences, resource
versions, adoption approvals and all reserved Hanko/mesh metadata except the
exact tenant label. Existing foreign or unassigned live objects are refused,
even with matching specs. Typed and real API dry-run preflight validates the
entire object set before checkpointing or real content writes. Local fields are
preserved, writes use current UID/resourceVersion and no ForceOwnership.

## Independent local trust and rotation

The deployment's `HANKO_FLEET_TRUST_CONFIGMAP` selects a same-namespace ConfigMap
whose `trust.json` uses `hanko.sh/fleet-trust/v1alpha1`. Hub plans and HankoTenant
specs cannot select or edit this name. A trust document is at most 64 KiB with at
most 32 unique key IDs. Each entry has issuer, a raw 32-byte Ed25519 public key
(unpadded base64url), notBefore/notAfter, up to 64 exact scope tuples and up to 16
approved source names. No wildcard scope or fetched key is supported.

Provision the ConfigMap and protect create/update/delete with the supplied
admission-policy pattern before enabling signed mode. Only independent local
policy administrators may change keys, expiry or scope; ordinary CR authors and
the operator do not gain that authority. Customize the policy's namespace/name
with the process configuration. Never store a signing private key or Hub bearer
in this ConfigMap, status, logs or fixtures.

Rotate through a fresh locally approved key ID, overlap only the approved
validity window, publish a new higher-sequence plan, then retire the old entry.
Removing/expiring a key revokes future verification using it. Trust is read through
the uncached API before verification and conditional writes; changed UID/version
halts the current apply. Revocation does not undo earlier Kubernetes/provider
effects or instantly invalidate already issued IAM tokens.

## Durable acceptance and replay rules

`status.fleetPlan` records sequence, signed payload identity, previous identity,
applied identity, public key ID, tenant UID and expiry. It contains no content,
credentials, token hashes, signatures or private keys. Acceptance is persisted
with optimistic concurrency before any real object create or apply.

- Lower sequence: refuse, including after restart or a lost acknowledgement.
- Same sequence with different payload identity: refuse a conflict.
- Same pending identity: reverify signature, target, source, time and current
  trust, then recover the conditional apply. Do not downgrade the high-water mark.
- Same applied identity: reverify and report current; do not replay content writes.
- Higher sequence: validate the complete content, persist its new checkpoint,
  apply conditionally, then persist applied identity. A failed status write is
  returned; it cannot be replaced by an error-status patch that silently advances
  execution.

Presence of a signed checkpoint permanently refuses legacy HMAC fallback for that
tenant UID. Missing/invalid trust or removal of the process setting is an error,
never a transition request. An operator predating this rule cannot enforce it:
suspend management before rollback, retain the newer CRD/checkpoint and review
actual effects. Do not clear status or downgrade/prune the CRD to force HMAC reuse.

Every content write rechecks current source intent, exact checkpoint, trust and
validity. These checks fence observations; they are not a distributed transaction
with Kubernetes or a provider. A change after the final read, admission/concurrency
failure or outage can leave an already applied prefix. Earlier effects are not
automatically undone and no exactly-once external action is promised.

## Refusal and heartbeat evidence

Checks run in verification order; the first failure supplies the reason. These
invariants are exercised in the [pure verifier tests](../../internal/fleetplan/verify_test.go),
[controller failure tests](../../internal/controller/hankotenant_fleet_test.go) and
[real HTTPS/API fixture](../../api/v1alpha1/fleet_plan_integration_test.go).

| Rejection reason | Testable violation |
| --- | --- |
| FleetEnvelopeInvalid | Empty, oversized, ambiguous, unknown-field or unsupported-version envelope. |
| FleetPayloadInvalid | Invalid/case-aliased/duplicate payload JSON or noncanonical base64url. |
| FleetTrustInvalid | Missing fields, wrong version, invalid key/scope/source bounds or duplicate key ID in the local trust document. |
| FleetTrustUnavailable | The locally configured trust ConfigMap cannot be read. |
| FleetTrustChanged | Its UID/resource version changed or deletion began during fetch/apply. |
| FleetKeyUnapproved | No locally approved exact issuer/key ID, including an unapproved rotation or revoked entry. |
| FleetKeyExpired | Selected key is outside its local validity window. |
| FleetSignatureInvalid | Wrong-length or cryptographically invalid Ed25519 signature. |
| FleetIssuerAuthorityMismatch | Selected issuer has no exact target scope tuple or approved source name. |
| FleetTargetMismatch | Invalid local target, absent cluster/tenant UID, or signed target differs from the current local identity. |
| FleetSourceInvalid | Unsupported contract version, non-full revision or invalid source digest. |
| FleetValidityInvalid | Nonpositive sequence, missing/reversed or excessive validity bounds. |
| FleetPlanNotYetValid | Issuance/start exceeds allowed future skew. |
| FleetPlanExpired | Current time is at or after signed expiry. |
| FleetCapabilitiesUnsupported | Nonempty requirements or mode other than all-or-refuse. |
| FleetRollbackUnsupported | A rollback reference is supplied before rollback execution is supported. |
| FleetContentInvalid | Closed object/typed schema, size/count or API dry-run validation fails. |
| FleetContentAuthorityInvalid | A reserved approval/ownership annotation or label is supplied. |
| FleetCheckpointInvalid | Malformed persisted sequence/identity or checkpoint tenant UID differs. |
| FleetPlanDowngrade | Signed sequence is below the durable high-water mark. |
| FleetSequenceConflict | Same sequence identifies different signed bytes. |
| FleetAuthorityChanged | Current tenant UID/generation/spec/checkpoint differs from the accepted observation; retry a fresh reconcile without overwriting that newer intent's condition. |
| FleetLegacyDowngrade | Signed checkpoint exists but the local signed-mode setting was removed. |
| FleetPlanFetchFailed | Exact HTTPS transport, response status/read or bounded-body contract fails. |

Existing bundle tenant/object/metadata conflicts retain their distinct reasons.
Public messages contain authored decisions, never remote payloads. Heartbeats
carry only plan sequence, identity and applied identity alongside bounded counts.
They do not attest provider convergence or authorize image updates/decommission;
the existing independent local approvals remain mandatory.

## Disconnected and rollout design boundary

The target #79 contract retains independently verified content for recovery,
revalidates current local trust and time without Hub, continues authorized
reconciliation only until expiry, then stops provider mutations and reports
Degraded. Reconnect refuses older/conflicting plans and accepts only newer valid
ones or a verified current identity. A controlled rollback must be a newly signed
higher-sequence plan referencing retained, verified prior content and current
scope; it is a forward desired-state change, not database/provider rollback.

Those offline retention/provider-expiry gates and rollback execution are not
implemented by the current verifier. Existing child reconcilers may continue
reconciling previously written declarations after Hub loss or plan expiry; do not
advertise offline fleet authorization until #79 qualifies that behavior. Partial
rollout, local pause, per-object capability findings and provider permission checks
remain #78. The installed tamper/replay/expiry/reconnect matrix and artifact leak
inspection remain #80. No production release or network enforcement follows from
this contract.
