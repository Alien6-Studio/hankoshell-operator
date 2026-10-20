# Signed fleet desired state

This is the operator-side contract for #76–#80 and ADR-049. It does not implement
Hub signing/distribution or qualify enterprise fleet operation. Keycloak retains
all native extensions. #75 remains the provider-portability evidence boundary;
this protocol binds a contract/source identity without inventing second-provider
conformance. Disconnected provider authority and referenced rollback are implemented;
the installed Fleet matrix and its exact-image evidence are described below.

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
| rollbackOf | Optional SHA-256 identity of retained previously accepted content. Requires a new higher-sequence signature and exact historical content, source and capability policy; a bare identity grants no authority. |
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
| FleetRollbackReferenceInvalid | Invalid, unretained or mismatched rollback reference/content/policy. |
| FleetContentInvalid | Closed object/typed schema, size/count or API dry-run validation fails. |
| FleetContentAuthorityInvalid | A reserved approval/ownership annotation or label is supplied. |
| FleetCheckpointInvalid | Malformed persisted sequence/identity or checkpoint tenant UID differs. |
| FleetPlanDowngrade | Signed sequence is below the durable high-water mark. |
| FleetSequenceConflict | Same sequence identifies different signed bytes. |
| FleetAuthorityChanged | Current tenant UID/generation/spec/checkpoint differs from the accepted observation; retry a fresh reconcile without overwriting that newer intent's condition. |
| FleetLegacyDowngrade | Signed checkpoint exists but the local signed-mode setting was removed. |
| FleetPlanFetchFailed | Exact HTTPS endpoint, authentication/refusal, response/read contract fails, or Hub is unavailable without a retained plan. |
| FleetPlanDisconnected | Hub unavailable; the retained plan remains verified and usable until expiry. Local phase/health are Error/degraded, not Synced. |
| FleetCacheInvalid / FleetCacheWriteFailed / FleetCacheTooLarge | Missing/replaced/tampered retained envelope, unacknowledged storage or envelope above the 900 KiB storage budget. |
| FleetClockRegression | Wall clock is more than 30 seconds behind the durable verified time. |

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
again through uncached authority checks before conditional content writes and
every native provider mutation, including a change after checkpoint acceptance.
Status remains visible; pause prevents fetching a new plan. Remove the pause through the same local
approval path; it never clears the accepted sequence.

A provider-role observation is valid only until its token expiry; subsequent
content guards refuse expired evidence. Native authorization remains authoritative
at actual child-controller writes. A tenant-specific client guard revalidates
local authority immediately before each mutating Admin API request; local pause,
revocation, altered intent/cache and expiry also fence in-flight connections.
Token acquisition and reads remain available for diagnostics; they grant no writes.
Trust/intent checks cannot form a distributed transaction: a change after the last
read can leave an already applied prefix, and revocation does not undo effects.

Additional refusal codes are FleetOperatorVersionInvalid/Unsupported,
FleetCapabilityInventoryUnavailable, FleetCapabilityUnsupported,
FleetPermissionDenied, FleetCapabilityRefused, FleetProviderScopeUnknown,
FleetProviderVersionMismatch,
FleetDependencyRefused, FleetPermissionEvidenceExpired and
FleetRolloutPolicyInvalid/Paused/Refused. Findings distinguish incompatible
capabilities, missing permissions, unavailable inventory and refused dependencies.

## Disconnected recovery and referenced rollback

An accepted plan is retained BEFORE its status checkpoint in a same-namespace,
immutable ConfigMap. Status binds its name, UID, signed identity, sequence and
acceptance time. Each read checks exact controller ownership/tenant labels,
immutability, bounded single-key content and current UID, then independently
verifies the signature, target, source, time, current local trust and high-water
mark. ConfigMap content is untrusted input, not execution authority. Plans up to
900 KiB can be retained (the wire envelope ceiling remains 1 MiB); larger plans
fail before acceptance or desired-state writes. Never place credentials in plans.

Only transport unavailability or HTTP 502/503/504 permits falling back to that
EXACT accepted plan. Authentication errors, redirects, malformed/oversized bodies,
wrong-target signatures and stale/conflicting returned plans are refused without
using them as cache replacements. A valid same identity resumes/reports current;
a newer valid sequence is checkpointed before conditional delivery. There is no
forced ownership over local or foreign fields. Local edits retain their existing
child-controller authority during valid offline operation; field conflicts on
reconnect remain refusals. Rollback does not prune omitted objects.

Registration of the tenant's Keycloak route happens before any Hub request,
including on restart. A separately guarded client prevents one tenant's pause or
expiry from affecting the installation client or another tenant. Missing named
registrations keep the distinct TenantClientUnavailable reason and never fall
back to the installation client. The guard reads current tenant/trust/cache from
the uncached API before EVERY administrative mutation, including deletions and a
second write in a running reconcile. It blocks absent authority, altered tenant
intent, revoked keys, local stop controls and strict expiry. Reads and native
token acquisition may still run; native Keycloak permissions remain authoritative.
A request already dispatched before a local change cannot be recalled.

Hub loss reports Error/degraded with FleetPlanDisconnected; it never updates
LastSync or claims a live heartbeat. No mesh fetch, decommission or self-update
is attempted on the offline path. A missing/expired Hub credential can use an
already established exact tenant/cluster checkpoint locally; it never enrolls a
replacement identity or rotates provider credentials offline. Restoring Hub
credentials remains an administrator action. Invalid or mismatched identities
are refused. With no accepted cache, first enrollment cannot proceed offline.

The durable verified time rejects backward clock jumps beyond the 30-second
skew. Once observed expired, that identity stays expired even if the wall clock
moves back; only a newly signed higher sequence with fresh validity can renew
authority. Availability depends on the local Kubernetes API, current local trust
and the reachable provider; Hub HA is outside this contract.

For rollback, the publisher signs a NEW higher-sequence plan with fresh validity
and rollbackOf pointing at the retained previous envelope. Historical verification
checks that envelope at its acknowledged acceptance time and also checks its key
against CURRENT local trust/time. Candidate content, source, target, contract,
mode and capability requirements must exactly equal the reference. Unretained or
revoked references fail closed. The durable journal records the last sixteen
accepted sequence/identity/time/rollback-reference transitions; replay does not
append a transition. This is forward desired-state reconciliation, with no
provider database rollback and no deletion of foreign or omitted objects.

Current, previous and active rollback-reference caches are retained. After an
acknowledged transition, best-effort garbage collection uses exact ownership and
UID/resourceVersion preconditions, and considers only obsolete identities from
the bounded accepted journal. Unacknowledged orphan caches are never trusted or
overwritten; administrative cleanup may be needed after prolonged API failures.
Status/cache write failures never substitute an error patch for acknowledgement.

Unit tests cover cache corruption, stale/wrong-tenant/conflicting reconnect,
rollback verification, clock regression, sticky expiry and mid-reconcile writes.
Real API tests cover immutable/replaced cache UIDs, restart, pause, expiry after
checkpoint and rollback preserving foreign/omitted objects on all three supported
Kubernetes versions. A separate native HTTPS Keycloak fixture stops the actual
Hub listener and reconstructs the controller; this does not replace installed
image/chart evidence. The six-cell installed tamper/replay/expiry/reconnect matrix
and artifact inspection are described in the #80 qualification audit below. No production release or network
enforcement follows from this contract.

## Installed Fleet qualification (#80)

The installed harness is [tools/qualification/scenarios/fleet_installed_test.py](../../tools/qualification/scenarios/fleet_installed_test.py).
The mandatory CI job `installed-fleet` consumes the immutable scanned OCI artifact
from the same workflow, checks its exact revision/index/archive/evidence, then
installs the chart in a uniquely owned disposable cluster. All six combinations
of Kubernetes 1.35.0/1.36.2/1.37.0 and HTTPS Keycloak 26.7.5/26.8.0 must pass.
The aggregate source/chart check and scheduled reporting include this job; no
continue-on-error or partial matrix is accepted.

Each cell uses two dedicated tenant credentials, existing separate native realms,
an actual TLS Hub fixture and a protected trust ConfigMap. Signing keys stay in
private host temporary files, never in the Hub or operator. Tests compare desired
Kubernetes state and selected public provider fields across refused changes;
status, Events and controller-owned observation timestamps may legitimately change.
The external API fault proxy loses a checkpoint acknowledgement and holds later
traffic until the manager is stopped, proving restart before child delivery.
Hub disconnection stops the actual listener by removing its disposable pod.

The harness checks forged/tampered/replayed/downgraded/misrouted plans, source and
schema/metadata/validity bounds, unsupported capabilities, partial selection,
verified referenced rollback, cache immutability/replacement, durable clock
regression, offline drift repair and strict/sticky expiry. It also checks missing
tenant routing, overlapping objects, local trust write denial, refused image
updates and unapproved/expired/tampered decommission acknowledgements. Local key
expiry, invalid/missing trust, checkpoint UID replacement and removal of signed
configuration are exercised against the running manager. A held HTTPS response
allows actual trust/tenant changes during fetch; API admission refuses cache
creation independently of status writes. Oversized retained envelopes are also
refused. Failed
runs remain `complete: false`; an implemented harness alone is not evidence that
these installed scenarios passed.

Public reports allow only pinned versions, source/image/fixture hashes, counts,
boolean assertion results and completion times. Credential/error-body canaries,
signing private keys and JWT patterns are checked in logs, Events, CRs,
ConfigMaps (including decoded envelopes), Hub reports and artifact inputs.
Known fixture credential/TLS Secrets remain private inputs and are never uploaded.
Failure diagnostics use the existing bounded redacting collector. kindnet does
not enforce NetworkPolicy; these cells do not qualify network enforcement,
enterprise fleet topology, production publication or Hub signing/distribution.

### Independent command and transport authority

In signed mode, an accepted checkpoint also pins `hubEndpointHash` before child
writes. Changing the outgoing credential destination requires an exact entry in
protected `rollout.json.hubs`, using `{ "target": <complete target tuple>,
"endpoint": "https://approved-hub.example.test" }`. Up to 64 unique targets are
allowed. Provision this list before initial synchronization to constrain the first
identified Hub call too. Without a list or prior checkpoint, first enrollment
retains the independently declared local tenant destination. Every signed Hub
endpoint must be exact HTTPS with no userinfo, query or fragment. Rotation,
heartbeats and command confirmation refuse redirects; signed error reports and
Events contain only locally authored reasons, not remote response bodies.

Fleet decommission additionally requires a protected `rollout.json.commands`
entry with the complete target, `action: decommission`, and an `identity` derived
by [fleetplan.DecommissionIdentity](../../internal/fleetplan/authority.go). The
versioned domain-separated SHA-256 binds exact target UID, requestedAt and deadline
normalized to UTC. The operator first checks the command's existing deadline and
current signed plan authority. A different target or changed timestamp cannot
reuse approval. Up to 64 unique target entries are allowed. Hub possession of a
bearer token, or a valid plan signature, does not grant this local approval.
Approved decommission still uses the existing confirmation-before-RBAC/Deployment
removal ordering; this approval is not an image-update authorization. Review the
release-wide uninstall effect before granting a command for a shared operator.

Dedicated Keycloak credential Secrets may supply optional `ca.crt` alongside
HANKO_KEYCLOAK_URL, HANKO_KC_CLIENT_ID and HANKO_KC_CLIENT_SECRET. An explicitly
empty or invalid CA fails closed. The connection uses this CA directly rather
than silently borrowing the installation client's provider or trust.

HankoTenant refusal Events are bounded and emitted on acknowledged condition
transitions. Synced conditions carry the observed tenant generation. The manager
ignores its own status-only updates while retaining explicit local generation,
annotation and label changes plus the existing requeue cadence.

### Qualification audit

On 2026-10-15 all six local installed cells completed with 69/69 assertions each
(414 assertions). Each cell used a real Linux arm64 Kubernetes API, HTTPS
Keycloak and Hub, and the installed chart/operator. The committed reports contain
only the public evidence allowlist; they are nonpublishable qualification inputs.

| Kubernetes | Keycloak 26.7.5 | Keycloak 26.8.0 |
| --- | --- | --- |
| 1.35.0 | [69/69](../qualification/fleet/2026-10-15/kubernetes-1.35.0-keycloak-26.7.5.json) | [69/69](../qualification/fleet/2026-10-15/kubernetes-1.35.0-keycloak-26.8.0.json) |
| 1.36.2 | [69/69](../qualification/fleet/2026-10-15/kubernetes-1.36.2-keycloak-26.7.5.json) | [69/69](../qualification/fleet/2026-10-15/kubernetes-1.36.2-keycloak-26.8.0.json) |
| 1.37.0 | [69/69](../qualification/fleet/2026-10-15/kubernetes-1.37.0-keycloak-26.7.5.json) | [69/69](../qualification/fleet/2026-10-15/kubernetes-1.37.0-keycloak-26.8.0.json) |

- Image source: `248395147d5170d28ac12aca486c48b00ad3d7ba`.
- Exact OCI index: `sha256:72ae648871a524c36fd2642b3fff808f4f7f2ed7faf69a04097495f218ee9e61`.
- Archive SHA-256: `886e670e3cf4e25bbdbccb037c01c79a5c91501af37972af018789a9f9be6869`.
- Harness revision: `de3f760af7f4b931a63ef34b6311c043e700e5bf`;
  Fleet script SHA-256: `2a39cb170c072b53d22db492c3e35568c48df8513b2bb2d5dfd4b136d48d651a`.
  This revision changes only the external fixture relative to the image source;
  binary, chart and OCI build inputs are unchanged.
- Trivy 0.75.0 scans passed for both linux/amd64 and linux/arm64 with the reviewed
  policy and database updated on 2026-10-15. Scan evidence stays in the local
  `.tools/fleet-installed-qualified-oci/evidence` directory.
- Source regression: 2,173 Go tests, 264 script tests, 63.36% statement coverage
  with every reviewed floor met. The preceding API qualification passed 231 cases
  on each supported Kubernetes version; only command-log redaction changed
  production code afterward, and its regression/mutation tests passed.

These results qualify this local image/harness cut. Full CI on the final pushed
revision remains required before merge, including its Linux amd64 installed cells
and every existing source, CodeQL, OCI, workload, system and rehearsal gate.
The preceding complete CI run
[38796511058](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/38796511058)
passed on `a6cd98d111b4bf5f672b305fef215cb8c3ab8235`.
No production trust, enterprise topology, network enforcement or release is
qualified by these disposable local cells.
