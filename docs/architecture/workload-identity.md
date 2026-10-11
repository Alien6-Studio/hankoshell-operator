# Workload identity contract — Phase 6A

This document selects an implementation contract for Phase 6 of the first public
`0.1.0` roadmap. The active version remains `0.1.0-dev.0`, development. It does
not implement the API examples below. The qualification fixture changes only
uniquely named disposable clusters and servers. Production trust (#21), release
publication, existing IAM grants and Phase 7 remain separate work.

## 1. Problem statement

A dedicated Kubernetes workload should authenticate its existing M2M concept,
`HankoServiceAccount`, without a static client secret in its Pod:

```text
Pod / dedicated Kubernetes ServiceAccount
  → kubelet projected, audience-bound short-lived JWT
  → Keycloak federated client authentication + client_credentials
  → Keycloak client access token
  → independently authorized resource/API
```

HankoShell manages configuration, ownership and fresh local authorization. It
does not issue, transport, persist or periodically refresh workload JWTs. The
workload owns its PodSpec and token consumption. Authentication does not add
resource permissions; the existing resource-server and organizational contracts
remain authoritative.

## 2. Terminology

* **Kubernetes principal:** `iss` plus `system:serviceaccount:<namespace>:<name>`.
  The signed JWT also includes ServiceAccount and, for projected tokens, Pod/node
  UID claims. Native Keycloak matches issuer/subject, not those Kubernetes UIDs.
* **Cluster anchor:** administrator-reviewed current cluster identity, comprising
  the `kube-system` Namespace UID and the API server CA SHA-256 fingerprint.
  It is a local authorization dependency, not an extra signed JWT condition.
* **Trust:** one realm-scoped native `kubernetes` identity provider, shared by
  separately owned M2M clients. Its Kubernetes issuer differs from Keycloak's
  realm issuer, which is the required **assertion audience**.
* **Client identity:** Keycloak realm identity, client ID and native client UUID.
  The resulting access-token subject is the Keycloak service-account user.
* **Binding:** approved cluster anchor, namespace, ServiceAccount name and UID.
  Names locate objects; approved UIDs authorize local configuration.
* **Configuration proof:** fresh, complete provider read-back associated with a
  locally sealed plan and current Kubernetes dependencies.
* **Authentication proof:** actual workload assertion accepted by Keycloak and
  an authorized API exercised. A Ready condition or mesh projection cannot
  substitute for this proof.

## 3. Current foundations and required preservation

The inventory covers the complete types/controllers and their integration
contracts, rather than treating similarly named fields as federation:

| Foundation | Existing behavior | Phase 6 consequence |
| --- | --- | --- |
| `api/v1alpha1/hankoserviceaccount_types.go`, `internal/controller/hankoserviceaccount_controller.go` | M2M client creation, secret retrieval/recovery/rotation, UID ownership, reserved-client and cross-kind guards, claims, imported Observe latch, adoption and finalizers | Extend this identity; omitted authentication still means Secret. Do not create a second machine identity CRD. |
| `api/v1alpha1/hankomeshservice_types.go`, `internal/controller/hankomeshservice_controller.go` | identityRef to HankoServiceAccount, named Kubernetes SA, selected ready Pods, Service/SA/node UIDs, tenant/realm checks and transport audit projection | Match the same approved workload UID when federation is explicit; retain mesh audience as resource audience. |
| `api/v1alpha1/application_runtime_types.go`, `application_runtime_integration_test.go` | Workload is explicitly an authorization anchor, not federation; pre-existing outputs, named-target RBAC, UID consent, deterministic revision, stale-source rejection and field-only cleanup | Reuse delivery principles and shared structural validators; do not reinterpret existing application bindings or deliver JWTs. |
| `api/v1alpha1/hankoapplication_types.go`, `internal/controller/hankoapplication_controller.go`, `docs/architecture/application-identity.md` | Typed OIDC/SAML plans, reserved roles/claims, owner UUID checks, runtime delivery and durable application rotation checkpoints | Keep OIDC/SAML, reserved `act`/`may_act` guards, existing client conflict resolution and protocol semantics. |
| `api/v1alpha1/hankorealm_types.go`, `internal/keycloak/identity_providers.go` | Realm-owned brokers with an open native config map, additive configuration and mapper cleanup | Do not put the new workload trust under opaque broker management. Detect conflicts with existing realm declarations. |
| `docs/architecture/iam-contract-engine.md`, `internal/iamcontract` | Domain intent → local sealed provider plan → bounded observation; status/hashes are evidence, not executable authority | Add domain capabilities and complete read-back; no universal provider interface or remote plan execution. |
| `docs/keycloak-permissions.md`, `docs/secure-deployment.md` | Explicit per-capability authority, TLS/response bounds, named Kubernetes grants, actual-provider and installed-system gates | Preserve every security gate. Existing envtest API matrices do not contain kubelets or prove projected-token rotation. |
| `HankoIssuer` | Public OIDC authority routed to a Hanko realm/API facade | Keep separate: it is not Kubernetes issuer trust. |
| Phase 5 adoption | Exact source/realm/provider identity, explicit reviewed candidates and receipts, closed preservation, fresh UID checks, no ownership by name | Extend the closed schema before admitting federated clients or typed trusts. |

The current service-account rotation path is not the application's durable
checkpoint implementation: a provider rotation followed by a failed Secret write
can currently be retried. Phase 6 migration must add a durable transaction to
HankoServiceAccount; it must not describe current status as an exactly-once
credential journal. Current native application observations also omit
`clientAuthenticatorType`; adding typed federation requires extending their closed
preservation boundaries, not setting generic client attributes as a shortcut.

## 4. Native Keycloak capability and qualification boundary

The supported targets are **26.7.5 and 26.8.0**. Qualification uses their pinned
official images and real Kubernetes **1.35.0, 1.36.2 and 1.37.0**. Run
`scripts/workload-identity-probe.py`; its filtered JSON records exact native
representations and observed decisions. Source and matrix evidence accompany
this contract. Fixture success proves these native semantics, not a future
installed HankoShell controller.

Exact native mapping:

```json
{
  "alias": "workload-kube",
  "providerId": "kubernetes",
  "enabled": true,
  "config": {
    "issuer": "https://<approved-kubernetes-issuer>",
    "allowedClockSkew": "0",
    "fedClientAssertionMaxExp": "600"
  }
}
```

POST/GET/PUT/DELETE live under
`/admin/realms/{realm}/identity-provider/instances[/{alias}]`. GET returns a native
`internalId`, `types: ["CLIENT_ASSERTION"]` and `hideOnLogin: true`. The typed
adapter owns declared workload fields and preserves only qualified non-managed
fields. A display name, issuer spelling or alias alone never proves ownership.

The client is `protocol=openid-connect`, confidential, enabled, with
`serviceAccountsEnabled=true`, `clientAuthenticatorType="federated-jwt"`,
`attributes["jwt.credential.issuer"]` equal to the **provider alias**, and
`attributes["jwt.credential.sub"]` equal to the exact Kubernetes subject.
Client credentials, standard/implicit/direct grants and full scope are separate
settings; disable unnecessary grants/full scope and preserve declared resource
permissions. Keycloak can retain an inactive native secret. Secretless means no
active secret authentication or secret delivery, not a claim that its database
contains no generated secret bytes.

The token request uses `grant_type=client_credentials`, `client_id`,
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, and
the actual projected token as `client_assertion`. The assertion audience is one
exact Keycloak realm issuer. It is neither the token endpoint URL nor a resource
server's access-token audience.

**Version-dependent discovery:** 26.7.5 discovers
`<issuer>/.well-known/openid-configuration` and then its `jwks_uri`. 26.8.0 adds
`issuerDiscoveryUrl`; validation retrieves discovery and persists resolved
`issuer` and `jwksUrl`. Removing discovery override removes the persisted
`jwksUrl`. An override must resolve to the independently approved issuer and
cluster/JWKS source; do not accept Keycloak silently rewriting source identity.
26.7.5 must report this requested override unsupported, rather than accept an
opaque key that has no native effect.

In-cluster Keycloak can use its mounted discovery SA token and Kubernetes CA.
This is a Keycloak discovery credential, distinct from a workload assertion and
never an operator-issued token. External Keycloak needs a verified, reachable
issuer/discovery/JWKS route and explicit CA trust. The external fixture publishes
only discovery/JWKS through an exact GET-only anonymous grant; it mounts no
Kubernetes credential or kubeconfig. Publishing those public keys is an
administrator choice, not a production RBAC change performed by HankoShell.

Fresh realms have the native `federated-jwt` client-flow alternative. A legacy or
custom effective client flow can omit it. The controller must read the effective
realm binding and recursively validate the complete client execution graph,
including disabled branches, overrides and unsupported custom executors. Feature
availability alone is insufficient. Missing/incomplete execution or missing read
permission fails closed before activation. Flow repair is an external
administrator prerequisite; HankoShell will not own or mutate opaque auth flows.
Built-in flow deletion is refused, but an administrator can change an existing
execution's requirement through Admin REST. The probe disables/restores that
execution and measures authentication refusal/recovery. A `builtIn` flag does not
prove that the effective execution graph is immutable.

Primary versioned sources: the
[26.7.5 Kubernetes provider](https://github.com/keycloak/keycloak/tree/26.7.5/services/src/main/java/org/keycloak/broker/kubernetes),
[26.8.0 Kubernetes provider](https://github.com/keycloak/keycloak/tree/26.8.0/services/src/main/java/org/keycloak/broker/kubernetes),
and each version's
[26.7.5 client authenticators](https://github.com/keycloak/keycloak/tree/26.7.5/services/src/main/java/org/keycloak/authentication/authenticators/client) /
[26.8.0 client authenticators](https://github.com/keycloak/keycloak/tree/26.8.0/services/src/main/java/org/keycloak/authentication/authenticators/client).

## 5. Kubernetes token semantics and lifetime

The Pod owner declares an explicit dedicated ServiceAccount and projection:

```yaml
spec:
  serviceAccountName: worker
  automountServiceAccountToken: false
  volumes:
    - name: workload-assertion
      projected:
        sources:
          - serviceAccountToken:
              audience: https://keycloak.example/realms/example
              expirationSeconds: 600
              path: assertion.jwt
```

Mount the volume read-only at a documented path, for example
`/var/run/hanko/assertion.jwt`, without `subPath`; reread it for each authentication.
Do not cache one JWT for the process lifetime. The kubelet handles renewal. The
fixture obtains the primary evidence from an actual Pod projection and makes an
HTTPS client-assertion request **inside the Pod**. Separate TokenRequests test
real namespace/SA/audience/lifetime variations. No synthetic signed token is a
positive proof. Signature corruption is a negative test only.

The observed token binds issuer, subject, a single audience, `iat`, `nbf`, `exp`,
namespace and ServiceAccount UID, plus Pod/node identity for the projection. These
claims are signed; that does not imply every consumer checks each claim. Kubernetes
TokenReview checks live object binding. Native Keycloak validates signature,
issuer, exact single audience and active dates, without TokenReview or SA/Pod UID
comparison. Deleting a Pod/SA therefore does not immediately revoke its assertion
at Keycloak. A deleted Pod can additionally have an API-server grace period;
deleting/recreating the SA removes the original UID from TokenReview.

**Lifetime decision:** recommend/default **600 seconds**, accept explicit
**600–3,600 seconds**, and configure native assertion maximum age to the same
value, with skew zero. A cluster refusing the requested duration or issuing a
different lifetime is a qualification failure; do not request a longer token as
fallback. The supported native setting is an **age limit**, not a maximum JWT
`exp - iat`: when `iat` exists, a fresh 7,200-second token is accepted, and a
900-second token with maximum age 600 is rejected after age 600 while still
unexpired. Effective acceptance ends at `min(exp, iat + maxAge)`, subject to
native clock comparisons. Runtime metadata must not call this a cryptographic
restriction on Kubernetes token lifetime. Kubernetes cluster-wide issuance
limits and Keycloak access-token lifetimes remain independent; the fixture
reports requested versus actual durations and observes real kubelet rotation.
The server's token-expiration flags and an intentionally excessive TokenRequest
are recorded to distinguish its configured ceiling from the tested product range.
Long assertions in this limit probe stay only in fixture memory; they are never
workload recommendations or persisted credentials.
The unmodified kind 1.36.2 server has no explicit expiration-cap flags and even
issues the requested 1,000,000,000-second assertion; do not infer a universal
24-hour Kubernetes ceiling. The required matrix records the other exact servers.
Native acceptance is still bounded by the explicitly configured assertion age.

Maximum age belongs to the shared **trust**, not to each client. A client's
recommended projection must be between 600 and the smaller of 3,600 seconds and
that trust's maximum age. Refuse `ProjectionExceedsTrustAge`: kubelet renewal of
a longer-lived projection can occur after Keycloak starts rejecting it. Publish
both projection duration and shared native maximum age in public metadata.
Changing the trust limit affects every referenced client and requires explicit
review of the complete dependent inventory; no client reconcile may silently
raise the shared limit to accommodate itself.

Assertions are reusable during their acceptance window. Access tokens already
issued can outlive that window; urgent revocation requires independent client,
session/resource policy controls and actual resource verification. See
[Kubernetes service-account semantics](https://kubernetes.io/docs/concepts/security/service-accounts/)
and [projected tokens](https://kubernetes.io/docs/concepts/storage/projected-volumes/#serviceaccounttoken).

## 6. Trust boundaries and threat model

| Threat | Bound / residual risk | Required response |
| --- | --- | --- |
| Compromised Pod | Can read/replay its assertion and use client permissions until assertion age/expiry and issued access-token lifetimes end | Dedicated SA, exact audience, short age, minimal client scopes, TLS and resource enforcement; revoke independently during incidents |
| Pod creation under an authorized SA | Pod/TokenRequest authority can mint a genuine assertion for that principal | Restrict Pod creation, SA selection, exec and token subresource authority; HankoShell cannot isolate mutually hostile Pods sharing one SA |
| SA recreation with same name | Native subject stays identical; new UID token can authenticate the old configured client | Explicit approved UID, fresh reads and watch/requeue; revoke/disable strictly owned client on detected mismatch; no instantaneous cryptographic UID rejection |
| Compromised cluster issuer/signing key | Can impersonate every subject trusted through that issuer in each linked realm | Scope trust, protect signing keys and administrators, disable trust/clients and rotate/requalify keys; cluster admins are superior authorities |
| Interception / replay | Native Kubernetes assertion reuse is permitted; JWT theft is credential theft | Verified TLS, no token diagnostics/storage, minimal window; no claim of single use or sender binding |
| Audience confusion | API-only and multiple-audience assertions are refused by native validation | Exactly one realm issuer; keep resource audience distinct |
| Cross-cluster issuer collision | Default issuer DNS name is often identical across clusters; issuer string does not identify a cluster | Pin namespace UID and CA/source, resolve actual discovery/JWKS, refuse ambiguous same-issuer trust in a realm; never merge trusts by URL spelling |
| Namespace/name collision | Subject includes both names, but not immutable SA UID | Match complete subject and approved current UID; reject empty/default SA and implicit namespaces |
| Foreign provider or client | Matching aliases/IDs and status can be forged or stale | Native UUID, reviewed receipts, strict UID markers, fresh source and provider reads, foreign preservation |
| Keycloak administrator | Can edit clients, flows, providers and ownership markers | Outside HankoShell's protection boundary; avoid concurrent edits, independently audit actual provider state |
| Kubernetes administrator / trusted CRD writer | Can replace local anchors or approve a new principal | Superior authority; constrain spec/consent/RoleBinding writers and review changes |
| Controller credential theft | Native roles permit broader realm-wide operations than controller code | Separate profiles/realms where possible; ownership checks do not reduce native credential authority |

UID checks are local configuration authorization, not a native authenticator
extension. Detection and a provider write are asynchronous, and Keycloak has no
conditional multi-system transaction. There is a residual interval before
disablement; existing access tokens may also remain valid. A deployment requiring
immediate cryptographic SA UID revocation or per-request live TokenReview cannot
claim this native contract satisfies it.

## 7. API decision and capability model

**Choose B: a namespaced, typed `HankoWorkloadTrust`**, scoped to one exact realm
and native provider. It is a future seventeenth CRD, introduced in P6.2 only after
this contract. It is justified because several M2M clients share one realm-wide
trust and because a managed trust must work with an external/Observe realm without
taking ownership of that realm. HankoServiceAccount remains the only M2M identity.

| Alternative | Decision |
| --- | --- |
| A: typed HankoRealm extension | Realm lifecycle/authority coupling prevents independent trust ownership in an observed external realm; rejected |
| B: independent typed trust | Explicit single owner, shared references, independent Observe/adoption/deletion; selected |
| C: derive trust from each HankoServiceAccount | Native issuer is unique per realm; competing clients would need a fully qualified aggregate ownership protocol; rejected |
| D: extend RealmIdentityProvider.Config | Open broker config and existing realm lifecycle cannot establish closed workload semantics/independent ownership; rejected |
| Reuse HankoIssuer | Public facade authority has different origin, lifecycle and security semantics; rejected |

Conceptual, **not currently accepted API**:

```yaml
kind: HankoWorkloadTrust
spec:
  mode: Manage                  # Observe is read-only
  realmRef: example             # same Hanko namespace, may resolve external realm
  keycloakAlias: cluster-one
  provider: Kubernetes
  kubernetes:
    issuer: https://approved-kubernetes-issuer.example
    discoveryURL: https://approved-discovery.example # optional, native 26.8 only
    clusterAnchor:
      kubeSystemNamespaceUID: <independently-reviewed-current-uid>
      apiServerCAHash: sha256:<independently-reviewed-current-ca-digest>
    assertionMaxAgeSeconds: 600
---
kind: HankoServiceAccount
spec:
  realmRef: example
  clientID: worker
  authentication:
    mode: Kubernetes
    kubernetes:
      trustRef: cluster-one
      workload:
        namespace: workloads
        serviceAccountRef: worker
        expectedUID: <independently-reviewed-current-serviceaccount-uid>
      expirationSeconds: 600
  # Optional delivery into an existing, explicitly authorized target:
  runtimeMetadata:
    configMapRef: worker-identity
```

Authentication omitted, or `mode: Secret`, preserves historical secret-based
manifests. Kubernetes-specific fields and Secret rotation/projection are mutually
exclusive with active Kubernetes mode. Reserve `jwt.credential.*` alongside
ownership/adoption/journal attributes; generic attributes cannot change mode,
subject, trust or native authenticator. Do not silently convert legacy generic
federation attributes; surface reviewed migration requirements.

Only the operator's current cluster is a qualified workload binding source in
Phase 6. Foreign issuers in fixtures are negative/external-provider evidence,
not a remote-cluster binding API. Trust/realm references stay in the Hanko
namespace; workload namespace is explicit and requires named direct-read grants.
Reject `default`, missing namespace, malformed names and absent expectedUID.
Replacing approved UIDs/anchors requires explicit authorized spec changes and
fresh approval, never a status-derived default.

The domain uses the IAM contract version/hash/plan conventions and a bounded
capability snapshot: `KubernetesWorkloadIdentity`, `FederatedClientAuthentication`,
`ShortLivedClientAssertion` (age and expiry semantics), `SecretFallback`, plus
version-specific `IssuerDiscoveryOverride`. Static adapter evidence names exact
qualified versions; actual credentials/flow/trust/binding are freshly validated
preconditions. Unsupported/lossy cases refuse activation. `Ready` means current
supported configuration with complete read-back and binding; it does not assert
a live token was issued. Authentication proof is separate bounded evidence from
the workload/qualification owner, not writable status execution authority.

## 8. Provider ownership and freshness

The trust CR owns exactly one native IdP configuration and its lifecycle. The
HankoServiceAccount owns its native client UUID, authenticator, federated subject,
declared scopes/claims and approved workload binding. No client owns or deletes
the shared trust. Kubernetes SA and Pod lifecycle remain workload-owned.

Before each mutation and after read-back, rebuild local sealed dependencies from
uncached source UID/generation/mode, realm source/provider identity, endpoint/CA,
trust UID/generation/cluster anchor, actual Kubernetes SA UID, approval, referenced
output UID/consent and cross-kind ownership inventory. Use the resolved provider
realm UUID plus endpoint identity, not just the Hanko realm reference spelling.
Check native IdP internalId/providerId/alias/issuer and strict trust UID marker;
check client UUID and service-account owner UID independently. Use a bounded
non-secret provider journal bound to UID, approved inputs and plan identity.

Reject duplicate alias/issuer managers, declarations in HankoRealm's broker list
and ambiguous native issuer/subject client mappings before writes. Two clusters
with the same issuer cannot share an implicit trust; qualified independent issuer
identities require separate realms or administrator-reviewed unique issuers.
There is no cluster-wide lock across unrelated operator installations; deployment
authority must prevent competing installations from managing the same native
realm objects. Native administrators can race the final read/PUT.

A lost POST/PUT acknowledgement is recovered by fresh exact identity, ownership
marker and journal read-back. Do not blindly repeat CREATE, rotate credentials,
rebind to a same-name replacement or trust status alone. A missing/malformed
journal or ambiguous state stops writes pending explicit review. Observation is
bounded and closed; unknown security-affecting fields cannot prove equality.

## 9. HankoServiceAccount lifecycle

Fresh Kubernetes mode preflights trust, effective client flow, current approved
SA and delivery consent before creating a federated client. No workload secret is
retrieved or projected; no automatic Secret rotation occurs. The normal operator
never calls TokenRequest or TokenReview for runtime credentials. A workload-owner
qualification probe provides separate authentication/API proof.

SA deletion/replacement makes current configuration evidence stale. Stop metadata
delivery and grants dependent on the binding. Freshly disable the strictly owned
federated client when the mismatch is confirmed; do not mutate a foreign client
or infer replacement approval. This containment must be implemented before
federated activation is enabled. It is asynchronous configuration containment,
not immediate invalidation of old assertions or access tokens.

Observe reads bounded actual supported semantics and reports candidates, without
provider/credential writes, secret retrieval, runtime delivery or Manage
finalizers. Imported-by latching remains effective. Changing desired mode alone
does not override it or approve adoption. Deletion of a Manage SA cleans only its
owned client, claims and authorized output fields; it never deletes the Kubernetes
SA/Pod or the shared trust. Foreign children/configuration block destructive
cleanup until reviewed.

Trust deletion requires a complete fresh reference/native-client inventory;
live dependents block deletion. Disable/delete dependent owned clients first,
preserve foreign dependents and require administrator review rather than cascade
through them. Inventory failure/overflow must not be interpreted as zero users.

## 10. Secret migration, explicit fallback and recovery

Both native versions select **one client authenticator**. Switching a client
from `client-secret` to `federated-jwt` rejects its retained secret; switching back
restores secret authentication. The fixture tests both directions and return to
federation. An inactive native secret is not a second active authentication mode.

There is a necessary distinction between *proof before secret deactivation* and
*proof before deleting the Kubernetes Secret*. Native Keycloak cannot prove
federated authentication on a still-secret-only **same client**. There is no
cross-system atomic method change or operator-held assertion to work around it.

**Supported default migration with proof before deactivation:** create a second
HankoServiceAccount/clientID in Kubernetes mode, referencing the same dedicated
approved workload SA. Keep the existing Secret client functional. The workload
owner prepares explicit projection/runtime configuration, exercises the new
client's assertion and authorized API, and switches consumers. An authorized
review then retires the old Secret client and cleans its owned Secret fields.
Each client has one active authenticator; this is a reviewed overlap of two client
identities, not implicit dual auth on the Kubernetes client. Resource permissions
must be independently declared/reviewed for the new client. Failure preserves the
old working client; explicit rollback points consumers back to it before retirement.

**Same-client transition:** supported only as an explicitly reviewed coordinated
cutover, with workload preparation and an acknowledged interruption risk. P6.3
must reject an ordinary mode edit on an existing active Secret client unless
such exact-identity approval exists. Preflight can prove configuration/prerequisites,
but authentication proof happens **after** native activation and **before** Secret
cleanup. This path cannot satisfy a zero-interruption/pre-authentication guarantee;
installations requiring proof before deactivation must use the default two-client
migration. Retain inactive native recovery material, not a Secret mounted in the
Kubernetes workload. Never mark a provider flip as proof of workload success.

For a coordinated same-client switch, persist a non-secret durable provider
transaction (source UID, previous/desired mode, binding/plan and step) before
changing authenticator. Read back native UUID/configuration before checkpointing
progress. A lost status write or restart reconstructs progress from native state
and the journal; it neither toggles authentication back nor repeats a rotation.
Cleanup requires an explicit administrator/workload-owner approval of the exact
current plan and successful real workload test; status booleans cannot grant it.
The operator does not collect or validate a stored workload JWT as proof.

The future typed `authentication.transitionApproval` contains
`strategy: CoordinatedCutover`, a bounded `requestID`, `expectedClientUUID`,
`reviewedStateHash` and `preparedWorkloadRevision`. It is explicit authorization
by a trusted spec writer, not proof that the operator tested a JWT. The initial
provider observation and sealed input/dependency hashes are captured before
mutation; the durable journal distinguishes the expected before/after native
states so a successful method change does not stale its own recovery. A separate
cleanup approval binds the same request, current binding/plan and reviewed
workload-test evidence. Source, SA/trust/output UID or authority changes stale
both approvals. Missing approval keeps the working native method and prevents
cleanup. The recoverable states are `Prepared`, `ModeApplied`, `AuthReviewed`,
`OutputsCleaned`, `Committed`; status records them but never drives a replay.

Explicit Kubernetes → Secret fallback first verifies ownership and recovers the
current native secret into the owned canonical Secret, with a durable checkpoint.
The owner prepares Secret consumption before approving the authenticator change.
If recovery/projection fails, keep Kubernetes active. If the native PUT succeeds
but status acknowledgement fails, read back Secret mode and recover the **same**
secret without rotating. Observe never performs fallback. If no recoverable native
secret exists, stop for explicit reviewed creation/rotation; do not fabricate a
successful fallback. Cleanup preserves unrelated output keys and requires current
UID consent. Return to Kubernetes uses the same explicit preparation/approval
and post-activation proof-before-cleanup rule, or a two-client migration.

Rotation is Secret-only. Kubernetes mode clears schedules without changing
inactive secret material. P6.3 must extend the durable checkpoint before rotation,
and qualify lost provider acknowledgement, Secret write failure, lost status,
restart and deletion after every step. No lost status write may remove the only
prepared functional method. External outages or an explicitly coordinated
cutover can still interrupt authentication; this contract promises no distributed
atomicity or automatic zero-downtime migration.

## 11. HankoMeshService relationship

IAM principal and transport identity remain different authorities. When
`identityRef` selects a Kubernetes-mode HankoServiceAccount, its approved cluster,
namespace, SA name and freshly verified UID must equal the mesh registration's
workload ServiceAccount and selected Pods. Any mismatch refuses projection and
clears current attestation. Unapproved recreated SA is rejected even if mesh's
independent same-name lookup succeeds. Secret-mode registrations keep their
current semantics.

`WorkloadID` remains the Keycloak clientID; `WorkloadServiceAccountUID` identifies
the current approved workload anchor. `Audience` remains the resource-server
audience, **not** the Kubernetes assertion audience. Mesh provides audit/projection,
not IAM enforcement, token issuance proof, a new authority grant or mTLS issuance.
Continuum/Hub credentials and transport boundaries remain unchanged.

## 12. External realms, existing providers and adoption

An external/Observe HankoRealm can locate a realm without owning its lifecycle.
An independently authorized Manage trust and Manage SA may own their exact child
objects there; realm Observe is not permission to mutate arbitrary children.
Each child has separate credentials/approval, fresh provider realm identity and
closed observation.

A matching existing Kubernetes IdP is Observe first, or a typed candidate with
exact native internalId, providerId, alias, realm/connection identity, approved
issuer/discovery/JWKS source, cluster anchor and complete preservation hash.
Explicit reviewed Phase 5-style adoption checks fresh identity/hash/UID ownership
absence and establishes a durable receipt. Name/issuer coincidence cannot approve
it. Unknown or credential-shaped config, foreign mappers, issuer collision or
incomplete read authority prevents automatic Manage adoption.

Existing federated clients likewise need the closed Phase 5 preservation schema
extended for authenticator, exact provider/subject, service-account/grant settings
and declared claims/scopes before adoption is supported. The current schema does
not qualify such adoption. A matching clientID plus workload names is insufficient.
No imported Observe object can retrieve an inactive secret or acquire ownership
through a mode edit. Preserve foreign client fields and broker configuration or
refuse unsupported preservation; do not replace an external client's attribute
map with a new default.

## 13. Permission model

Real constrained service clients in master use target-realm proxy roles with Full
Scope Allowed off, exact service-account role mappings and exact client role scopes.
Bootstrap administration provisions fixtures; normal operation does not use it.

| Capability | Target-realm authority | Native residual scope |
| --- | --- | --- |
| Typed trust GET/POST/PUT/DELETE | `manage-identity-providers` | Realm-wide broker read/write/delete, including unrelated IdPs; no claim of per-provider isolation |
| Federated client GET/POST/PUT/DELETE and explicit secret recovery | `manage-clients` | Realm-wide client/credential authority, not one-client isolation |
| Read effective realm/client authentication flow | `view-realm` | Realm security configuration reads; cannot repair/copy/write a flow |
| Observe IdP GET/list | `view-identity-providers` | Realm-wide IdP reads; native POST/PUT/DELETE denied; do not substitute a writer |
| Observe client | Existing qualified inventory read profile | Preserve the documented 26.7.5 client-secret privacy limitation |
| Change client authentication flow prerequisite | External administrator, normally `manage-realm` | Excluded from the workload controller's writer profile |

The effective activating writer therefore requires `manage-clients` plus
`view-realm`; a trust writer additionally requires `manage-identity-providers`
only where that capability is enabled. Separate credential profiles/installations
where isolation is needed. User management, realm DELETE/security PUT, new realm
creation, master administration, unrelated realm changes and impersonation are
explicitly denied to the constrained test profiles. A trust writer's unrelated
IdP write succeeds because that native role is realm-wide; code ownership checks
do not reduce stolen-credential authority.

Kubernetes grants are direct `get` on each named workload SA and, for optional
metadata, `get/patch` on each named pre-existing ConfigMap. Reuse the existing
named `kube-system` Namespace identity read; explicitly qualify required public
discovery/JWKS GET permissions. No Pod mutation, token subresource create,
workload Secret list/watch or automatic cross-namespace role grants are added.
Fallback may use only the existing separately authorized canonical Secret path.

## 14. Negative cases and evidence

The probe records exact HTTP status/OAuth error without error descriptions,
assertions or access tokens. Expected denial is HTTP 400/401; exact status is
retained instead of requiring all errors to use 401.

| Case | Native requirement / explicit limitation |
| --- | --- |
| Wrong audience, default API audience, multiple audiences | Reject; exactly one realm issuer |
| Wrong issuer from another real cluster | Reject; trusted source and signature must match |
| Wrong namespace / wrong dedicated SA | Reject exact subject mismatch |
| Wrong existing client | Reject client_id differing from resolved federated client |
| Cross realm with otherwise matching provider/client | Reject assertion audience for realm A at realm B |
| Expired genuine projected token | Reject after actual 600-second expiry; no synthetic clock/exp edit |
| Tampered signature | Reject modified signature of a real token |
| Default ServiceAccount | Reject through Hanko contract validation; native matching is not a dedicated-SA policy |
| Secret attempt in federated mode | Reject even with a retained native secret |
| Wrong provider alias/issuer, disabled/absent provider | Reject; do not invent or fall back to a broker |
| Missing client execution / serviceAccountsEnabled=false | Reject; capability flag alone is insufficient |
| Replayed valid assertion | **Accepted**; reusable bearer credential, not replay-resistant |
| Old assertion after SA deletion/recreation | **Accepted until age/expiry** by offline Keycloak; TokenReview rejects original UID |
| New same-name SA, different UID | **Accepted natively**; future local expectedUID guard and containment required |
| Fresh long JWT under max-age setting | **Accepted**; native maximum age is not JWT lifespan enforcement |

Fixture source and safe matrix JSON are the evidence for observed native results.
Future Hanko-only refusal/recovery criteria are implementation requirements, not
claimed outcomes of this Phase 6A script.

## 15. Installed-system qualification plan

P6.5 installs the scanned operator/chart, future typed trust and SA controllers,
and an independently authorized resource on actual supported Kubernetes and real
HTTPS Keycloak. A dedicated Pod projects a 600-second single-audience JWT, obtains
an access token without a secret and exercises a declared allow plus an
undeclared resource denial. Verify issuer/audience/signature and client authority
at the resource; JWT decoding alone is not authorization verification.

Test wrong audience/namespace/SA/existing client/realm/issuer, expiry, corruption,
default API audience, secret-method refusal, absent trust/flow and UID replacement.
Prove Hanko blocks current readiness and disables only the owned client after
replacement, while recording the native residual interval and existing token
lifetime. Retain a live Pod to observe kubelet rotation and correct rereading.

Exercise default two-client migration, explicit same-client approved cutover,
post-activation proof before Secret cleanup, explicit Secret fallback and return,
provider drift, foreign preservation, lost acknowledgements after each write,
lost status/restart, failed Secret/ConfigMap patch, removed/recreated consent,
adoption and finalizer ordering with shared/foreign dependents. Verify no workload
JWT in CRs, Secrets, ConfigMaps, logs, Events, Hub payloads or artifacts and no
TokenRequest/token mutation privilege on the operator SA. Phase 6A's native
fixture is necessary but does not claim this future installed-system proof.

Optional runtime metadata is a bounded versioned `workload-identity.json` document
(new `hanko.sh/workload-runtime/v1alpha1` delivery semantics), containing client_id,
token endpoint, realm issuer, assertion type, exact assertion audience, recommended
path and expiration, approved workload identity and source/binding revision.
It contains no JWT, access token, secret or token request result. Reuse Phase 3's
pre-existing target consent, exact owner and target/SA UIDs, current-generation
sealed proof, deterministic hash, named read/patch RBAC and field-only cleanup.
No target creation or workload injection is performed. Publication of metadata
proves configuration delivery, not successful authentication.

## 16. Unsupported and deferred behavior

No cryptographic SA UID matching, native TokenReview integration, immediate token
revocation, assertion single-use/sender binding, remote-cluster binding, operator
credential brokering, automatic PodSpec mutation, opaque broker/auth-flow repair
or unreviewed existing-client/provider adoption is supported. 26.7.5 discovery
override is unsupported. External private discovery requiring a token broker is
outside this contract; use a qualified administrator-owned reachable discovery
and CA route. Fail closed when capability, authority or complete preservation is
unavailable. Cloud/CNI/CSI and production issuer signing-key rotation require
installation-specific qualification; kubelet JWT renewal is not issuer-key rollover.

SPIFFE federation is documented only as a possible future issuer adapter.
Keycloak's versioned feature profiles classify SPIFFE as preview on both
[26.7.5](https://github.com/keycloak/keycloak/blob/26.7.5/common/src/main/java/org/keycloak/common/Profile.java)
and [26.8.0](https://github.com/keycloak/keycloak/blob/26.8.0/common/src/main/java/org/keycloak/common/Profile.java),
while Kubernetes and federated client authentication are default supported features.
Conceptually, Kubernetes uses an issuer plus namespace/SA subject and OIDC
discovery/JWKS. SPIFFE uses a JWT-SVID whose `sub` contains the trust domain and
workload SPIFFE ID, with keys obtained from a SPIFFE bundle endpoint rather than
Kubernetes discovery. Both authenticate an explicitly mapped machine client via
an external signed assertion; neither supplies Hanko's local SA UID approval or
single-use assertions. See the [upstream comparison](https://www.keycloak.org/2026/01/federated-client-authentication).
This is a source-based comparison, not an experimental SPIFFE qualification.
This contract adds no SPIFFE API, issuer adapter, trust bundle or workload
attestation claim.

## 17. Phase 7 boundary

The grant is `client_credentials` authenticating a machine client through a
Kubernetes assertion. It is **not** OAuth token exchange, JWT authorization grant,
on-behalf-of delegation, user impersonation, agent authority, an `act`/`may_act`
claim or a generic delegated credential service. Existing reserved authority
markers, user/realm isolation and organizational/resource-server semantics remain
unchanged. Any future delegation needs its own Phase 7 contract and qualification.

## 18. Implementation and migration order

[P6.1 #59](https://github.com/Alien6-Studio/hankoshell-operator/issues/59) is this
contract, primary-source/native qualification, threat model and safe matrix gates.
[P6.2 #60](https://github.com/Alien6-Studio/hankoshell-operator/issues/60) implements
typed trust ownership, capabilities, read-only prerequisite validation and
explicit adoption. [P6.4 #61](https://github.com/Alien6-Studio/hankoshell-operator/issues/61) implements binding UID
freshness/containment, runtime metadata consent and mesh coherence **before**
[P6.3 #62](https://github.com/Alien6-Studio/hankoshell-operator/issues/62) enables
federated activation. P6.3 extends HankoServiceAccount typed
authentication, durable credential/mode transitions and explicit fallback.
[P6.5 #63](https://github.com/Alien6-Studio/hankoshell-operator/issues/63) proves
the complete installed/migration system. Phase 6 remains open until
all implementation and installed proofs pass; the roadmap retains every later
phase required for the first public 0.1.0.

Apply future schemas before upgraded controllers; old manifests retain Secret
mode. Inventory/review existing opaque `kubernetes` brokers and generic federated
client settings, qualify closed candidates and approvals, prepare dedicated
workload SAs/UID consent and reachable discovery/CA. Prefer the two-client path
where interruption or proof timing matters. Keep source, provider and delivery
revision evidence current; stale status never grants migration, cleanup or
replacement authority. Rollback of code/YAML is not provider or credential recovery.

## 19. Questions resolved by real probes

| Question | Observed resolution |
| --- | --- |
| Which native IDs/configuration? | `kubernetes`, `federated-jwt`, provider alias in `jwt.credential.issuer`, exact subject in `jwt.credential.sub`; GET/PUT preserve native IdP internalId and its fixture UID marker; DELETE yields absence and authentication refusal |
| Persisted versus calculated fields? | Both return CLIENT_ASSERTION/hideOnLogin. 26.7.5 stores an unknown discovery key without resolving it; 26.8.0 calculates and persists issuer/jwksUrl. Only the latter override authenticates the foreign-cluster assertion |
| External reachability? | Both accept real assertions through a public verified issuer/discovery/JWKS route with only its CA mounted; no Kubernetes credential in external Keycloak |
| Effective flow prerequisite? | Fresh realms include the alternative. Missing/disabled execution refuses authentication. Built-in DELETE is refused; administrator execution-requirement PUT is allowed, so builtIn is not immutable execution proof |
| Can Secret and federation be exclusive? | Secret → federated → Secret → federated succeeds on the same native client; the inactive method is refused, and the original native secret is recoverable without rotation |
| Is replay prevented? | No; repeating the same actual projection returns HTTP 200 |
| Does native matching check SA UID? | No; the old assertion after SA deletion and new same-name/different-UID assertion both return HTTP 200. TokenReview switches from authenticated original UID to false |
| Actual expiry and rotation? | Projected lifetime is exactly 600; the live kubelet replaces it with the same SA UID; an actually expired held assertion returns HTTP 400 |
| What does maximum expiration mean? | Fresh long assertions are accepted. With max age 600, a 900-second assertion is refused after age 600 while still unexpired; this is age enforcement, not JWT lifespan enforcement |
| Cluster lifetime bounds? | 599 is refused, 600 is issued exactly. The fixtures also measure long requests and server flags; unmodified 1.36.2 imposes no measured ceiling even at 1,000,000,000 seconds. Product projection remains 600–3,600 and no greater than shared trust age |
| What authority is intrinsic? | IdP writer manage-identity-providers; client writer manage-clients; effective-flow reader view-realm. Scoped identities deny privileged user/realm/master/impersonation operations; unrelated IdP writes remain possible under the realm-wide trust-writer role |

The required six-cell matrix retains exact statuses, native representations,
minimal read/combined writer profiles, public cluster anchors and credential-free
artifact checks. It gates the PR's completion; incomplete reports do not qualify
the contract. Future controller-only freshness, adoption, containment and
installed-system behavior remain acceptance criteria of #60–#63, not fabricated
outcomes of the native fixture.

The selected public semantics deliberately retain the measured limits: local UID
approval with asynchronous containment, reusable assertions with short age,
explicit migration/fallback and no runtime token broker. Stronger immediate UID
revocation or zero-interruption same-client pre-authentication would require a
different native capability and a separate design decision.

### Reproduce the native qualification

Use Docker, OpenSSL 3, Python 3.12+ and the pinned tools; each invocation owns and
cleans two uniquely named kind clusters and its Keycloak containers/image:

```sh
python3 -m pip install -r scripts/requirements.txt
python3 scripts/install-system-tools.py /tmp/hankoshell-workload-tools
make workload-identity-probe KEYCLOAK_VERSION=26.7.5 KUBERNETES_VERSION=1.35.0 \
  KIND=/tmp/hankoshell-workload-tools/kind \
  KUBECTL=/tmp/hankoshell-workload-tools/kubectl OPENSSL=/usr/bin/openssl \
  WORKLOAD_OUTPUT=/tmp/workload-identity.json
```

Repeat both Keycloak versions across all three Kubernetes versions. On macOS use
the OpenSSL 3 path. Kubernetes 1.36.2 has no published `kindest/node` image: the
fixture downloads the exact official server archive, checks committed AMD64/ARM64
SHA-256 pins and builds against a digest-pinned kind base. It verifies the actual
server version; no patch-version substitution or image publication is allowed.
Only filtered JSON is retained/uploaded. Failed runs are explicitly incomplete
and never substitute for successful evidence. Real expiry/rotation/age tests
take at least ten minutes; no fabricated JWT/time shortcut is used.
