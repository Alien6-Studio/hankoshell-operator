# Signed fleet desired state

This is the operator-side contract for #76–#78 and ADR-049. It does not implement
Hub signing/distribution or qualify enterprise fleet operation. Keycloak retains
all native extensions. #75 remains the provider-portability evidence boundary;
this protocol binds a contract/source identity without inventing second-provider
conformance. #79/#80 own disconnected provider authority, rollback and the
installed fleet matrix.

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
| requirements, mode | Global capability requirements are hard stop conditions for the target. `all-or-refuse` refuses every object if one is incompatible; explicit `partial` selects compatible objects and refuses their incompatible dependencies. Both modes preserve all cryptographic, metadata and tenant guards. |
| minimumOperatorVersion | Optional semantic minimum, including prerelease ordering. A development binary does not satisfy the corresponding stable minimum. |
| objectRequirements | Up to 200 unique exact kind/name references to objects in content, each with up to 32 additional bounded capability identifiers. These add requirements; they cannot remove capabilities derived from actual specs. |
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
| FleetCapabilitiesUnsupported | Invalid requirement/reference bounds or mode other than all-or-refuse/partial. |
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
carry only plan sequence, identity and applied identity alongside bounded delivery
counts and the rollout evidence below.
They do not attest provider convergence or authorize image updates/decommission;
the existing independent local approvals remain mandatory.

## Capability-aware delivery and local stop controls

Cryptographic verification does not grant provider permissions. Every signed
object derives mandatory requirements from its actual kind/spec, even when Hub
omits explicit requirements. The local inventory combines the reviewed application
adapter capabilities, an exact qualified Keycloak version and a fresh effective
native-role snapshot for each target realm. It uses the tenant's registered client;
there is no fallback to another tenant or an unregistered shared connection.

| Capability | Current conservative support/permission boundary |
| --- | --- |
| iam.policy, realm.manage | Existing target realm on Keycloak 26.7.5/26.8.0; manage-realm and manage-events. Realm creation is outside this rollout profile. |
| realm.identity-providers | Same qualified versions; manage-identity-providers. Derived when broker configuration/mappings are present. |
| application.oidc, application.saml | Qualified application adapter support plus manage-clients. SAML includes the adapter's assertion-signing capability. |
| application.client-roles, application.token-claims | Qualified client-role/mapper capabilities plus manage-clients. Realm role-scope mappings additionally require realm.manage in this conservative profile. |
| service-account.manage | Qualified version and manage-clients. Token claims add their own requirement. |
| theme.build | Unsupported by this Fleet rollout profile; operational image/build authority is not inferred from provider roles. |

The native snapshot comes directly from a newly acquired client-credentials
response over the configured, verified HTTPS Keycloak connection. It is not an
incoming bearer authenticator or independently verified JWT: issuer/client/time
and exact `<target-realm>-realm` roles are inspected only in that trusted token
endpoint response. Roles from Hub, CR fields or persisted status are never accepted.
The read-only preflight also reads server info and the exact existing realm.
Minimal native admin grants may legitimately hide server version. In that case
an independent administrator must approve the exact version for the current
target UID and provider endpoint in the protected local document; Hub cannot
provide this assertion. A visible version that conflicts with that approval
refuses execution. A local pin is an administrator assertion of deployment
qualification, not runtime attestation; no extra master permission is requested.
Opaque/lightweight tokens, insufficient realm visibility, restricted inventory
clients and missing native-role evidence fail closed. No role is granted and no
provider mutation is used to probe permissions. See Keycloak's
[realm-specific native administration model](https://www.keycloak.org/docs/26.8.0/server_admin/#_per_realm_admin_permissions).
The native token/role model and this deliberately conservative intersection do
not claim support for arbitrary fine-grained provider policies.

Realm isolation requires a locally declared `HankoTenant.spec.realmRef`, and
per-object realm references must match it. Dedicated Keycloak/cluster isolation
retains the named tenant client and per-realm permission checks. No second-provider
parity or additional provider version is inferred from this inventory.

Global requirements and the minimum operator version are whole-target stops.
Per-object incompatibility in all-or-refuse mode prevents every desired-state
write. Explicit partial mode applies only selected objects; an incompatible
in-plan profile/realm also refuses its dependents. Invalid JSON, metadata, API
schema or live tenant ownership still refuses the whole plan in either mode.
Atomic refusal describes this preflight decision, not a transaction across writes.

`status.fleetRollout` and the matching Hub DTO include candidate sequence/identity,
selection hash, observed tenant generation, state and applied/refused/pending
counts. At most 32 findings identify a zero-based position and a locally authored
reason; `omitted` makes overflow explicit. Positions follow IAMProfiles, Realms,
Applications, Themes, ServiceAccounts array order. No object names, requirement
strings, provider payloads, tokens or personal data appear in these findings.
The API rejects oversized/duplicate findings and count totals above 200.

Partial delivery reports `FleetPlanPartial`, Error/degraded and a false Synced
condition. The accepted sequence still advances before selected writes, but
`fleetPlan.appliedIdentity`, `bundleVersion` and `lastSync` do not promote a partial
plan to full success. An acknowledged prefix is reported if a later write fails;
pending means unconfirmed delivery and may include an effect with a lost reply.
A completed identical selection is reverified without replaying its content.
Changed eligibility can retry the remaining forward desired-state selection.
These counts describe Kubernetes delivery, not completed provider convergence.

For a local pause/refusal, an independent policy administrator edits `rollout.json`
in the same protected trust ConfigMap:

```json
{"version":"hanko.sh/fleet-rollout/v1alpha1","overrides":[{"target":{"tenantID":"tenant-id","clusterID":"cluster-id","namespace":"auth","tenantName":"tenant","tenantUID":"current-tenant-uid"},"action":"pause"}]}
```

Use the actual current target tuple/UID. `allow`, `pause` and `refuse` are the only
actions; absent configuration allows evaluation. The closed document is at most
64 KiB with at most 64 unique exact targets. An invalid document refuses execution.
The same document may contain `providers`, for example
`{"target":{...},"endpoint":"https://keycloak.example.test","version":"26.8.0"}`.
Use the complete current target tuple in place of the abbreviated example; the
endpoint must exactly match the locally configured Keycloak client. Up to 64
unique target profiles are allowed, and only the two qualified versions are
accepted. Unmatched profiles grant no version assertion.
The independent ConfigMap admission policy protects this key along with publisher
trust. Hub cannot override it. Pause/refuse is checked before fetching a plan and
again through uncached authority checks before conditional content writes, including
a change after checkpoint acceptance. Status remains visible and credential
maintenance/heartbeats can continue. Remove the pause through the same local
approval path; it never clears the accepted sequence.

A provider-role observation is valid only until its token expiry; subsequent
content guards refuse expired evidence. Native authorization remains authoritative
at actual child-controller writes. Local pause stops new Fleet delivery, while
previously delivered child declarations retain their own reconciliation authority.
Stopping those provider mutations on plan expiry/offline restart remains #79.
Trust/intent checks cannot form a distributed transaction: a change after the last
read can leave an already applied prefix, and revocation does not undo effects.

Additional refusal codes are FleetOperatorVersionInvalid/Unsupported,
FleetCapabilityInventoryUnavailable, FleetCapabilityUnsupported,
FleetPermissionDenied, FleetCapabilityRefused, FleetProviderScopeUnknown,
FleetProviderVersionMismatch,
FleetDependencyRefused, FleetPermissionEvidenceExpired and
FleetRolloutPolicyInvalid/Paused/Refused. Findings distinguish incompatible
capabilities, missing permissions, unavailable inventory and refused dependencies.

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
advertise offline fleet authorization until #79 qualifies that behavior. The
installed tamper/replay/expiry/reconnect matrix and artifact leak
inspection remain #80. No production release or network enforcement follows from
this contract.
