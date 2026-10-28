# Delegation and agent authority

See the [accepted architecture decisions](decisions/README.md) for the underlying
operator, provider and trust boundaries.

This is the provider characterization and authority contract for
[RFC #68](https://github.com/Alien6-Studio/hankoshell-operator/issues/68).
The first implementation of #69 accepts typed intent and refuses unqualified
execution on stock Keycloak. **Neither supported stock Keycloak version qualifies
bounded delegated authority.** An explicitly installed experimental
[software delegation extension](https://github.com/Alien6-Studio/keycloak-bounded-delegation)
and selected realm profile provide a separate enforcement path for #69/#70.
Successful ordinary OAuth token exchange alone never enables that capability.

## Dedicated extension profile

The extension was explicitly authorized on 2026-10-17. Its generic Java kernel
is independent of Kubernetes; the operator adapter separately resolves local
actor/subject/audience references, verifies UID/tenant ownership and seals current
realm, effective memberships and composite closures into execution identity.
Only the advertised contract with the declared SDK eligibility is accepted;
task authorization additionally requires the exact independently qualified SDK.

Delegated permissions must be contained in ordinary declared grants to **both**
software identities. Excess findings identify the permission/resource/scope.
The bridge issues only attenuated UMA resource/scope permissions: ambient OAuth
scopes, realm/client roles and mapper claims are removed. Realm roles (including
effective composites), software clients and resolved organization groups can
constrain these grants. Unsupported authority dimensions are never unioned in.

Native non-secret metadata journals Prepared/Applied/Verified/Committed, gates
issuance until commit and survives restart/lost write acknowledgements. Actor
markers are reference counted across owned resource servers. Cleanup disables
issuance first, preserves foreign state and restores the previous exchange
setting after the last owner. Observe/import stay read-only; adoption refuses
delegation. No manage-realm/manage-users is added to the delegation writer.

Federated authentication preserves the native exchange activation only alongside
a valid actor marker bound to that client's own UID. This avoids treating an
owned delegation as authentication drift. General CR/adoption attributes still
cannot activate native exchange; malformed or foreign markers remain rejected.

`make keycloak-extension-test KEYCLOAK_VERSION=VERSION` builds Java and runs its
separate mandatory real-HTTPS profile gate. The extension is maintained in its
own repository. [The consumer pin](../../extensions/keycloak-bounded-delegation.json)
selects an immutable commit; builds fetch only that revision into an ignored
cache and retain its identity and the matching JAR SHA256 in each SDK report.
No Java implementation is duplicated in the operator tree. Stock characterization below remains
unchanged. The controller fixture uses a fake Kubernetes client with a real
provider; it does not replace #71's installed Kubernetes/cluster qualification.

The reviewed extension revision also provides optional native administrative
forms. Hanko remains the writer of its external `oauth.bounded-delegation.v1`
documents: manage those grants through their Kubernetes resources. The extension
refuses console/API grant creation for an audience with an external document;
it neither overwrites nor merges Hanko's configuration. Enabling `declarative-ui`
is an explicit server choice, independent of operator reconciliation. See the
[extension administration guide](https://github.com/Alien6-Studio/keycloak-bounded-delegation/blob/d9423db16e2bbe31bfb1dcc83c9a9441a18a6075/docs/administration.md)
for native permissions, writer conflicts and safe withdrawal. The extension's
Hanko's current matrix includes 26.7.5 and 26.8.1; existing 26.8.0 capability replies remain readable. The operator and extension retain separate qualification reports.

Public status adds observed portable delegation origin and bounds, not token
subjects or native user IDs. These experimental fields ship in v1.0.0 and are
covered by [the Go API contract](../go-api-contract.md).

## Installed qualification gate (#71)

The [required CI matrix](../../.github/workflows/ci.yml) runs all six supported
Kubernetes/Keycloak cells, including installed delegation and two-replica recovery.
The [recovery qualification](https://github.com/Alien6-Studio/hankoshell-operator/issues/96)
records the reviewed results. Every candidate source and chart change requires
its own exact-image CI; earlier runs cannot qualify a later binary.

`tools/qualification/scenarios/delegation_installed_test.py` requires the exact clean Operator revision,
its scanned OCI graph and the matching JAR already built/tested by the same CI run.
The required six-cell Kubernetes/Keycloak matrix runs the reviewed chart with
constrained credentials and three actual kubelet-bound federated workloads.
The broad ordinary resource grants deliberately exceed the narrow delegated
read grant. A separate HTTPS resource server verifies native RS256 signatures,
issuer, exact audience, expiry and resource/scope permissions before allowing access.
It also rejects a genuine UMA token minted for a separate ordinary resource server
and a freshly issued token from the foreign realm.

The scenarios cover native depth/replay refusal, identity/audience/resource
negatives, expiry and measured withdrawal, stale intent/provider outage recovery,
and accepted writes with lost acknowledgements at all four native phases.
Each phase also loses Kubernetes status and refuses the post-commit status write
before a second restart. There is no Kubernetes status write at the intermediate
native phases; the evidence names the actual post-commit failure boundary.
The fault selects only the verified `Ready` patch, allowing transient error reports
while native recovery progresses; the native `Committed` phase is still asserted.
The initial delegated graph has a measured 600-second convergence budget because
each native mutation rechecks live references. Grant withdrawal retains its
180-second bound. The [endurance report](https://github.com/Alien6-Studio/hankoshell-operator/issues/95)
records the separate measured workload and capacity observations.
The offline withdrawal comparison uses a declared 300-second token so it remains
valid throughout that budget; a separate 8-second token proves actual expiry.
An application metadata update must preserve the active delegation journal and
authorization graph. Application writes share the delegation transaction lock;
qualified sibling journals are excluded from application semantic observation.
An interrupted deletion retains foreign objects and blocks on incoming foreign
dependencies. The final scan covers current/retired logs and Kubernetes objects;
Hub is disabled and its payload count is explicitly zero.

These fixtures use one Kubernetes node and one Keycloak replica; they do not
qualify Keycloak cluster failover, signing-key rotation, human delegation or
production readiness. An offline JWT remains valid until its bounded expiry
after grant withdrawal.

When cleanup reports `CleanupConflict`, inspect and remove or migrate the foreign
dependency through its owner, then let Hanko retry. Delegated issuance is withdrawn
before graph cleanup. Existing UID-owned and adopted graphs both require complete
incoming-dependency observation; unavailable or over-budget reads retain the
finalizer. Do not force-remove the finalizer or delete foreign permissions to
make qualification pass. Coordinate native writers during the reviewed cleanup.

See the [local upstream discussion draft](keycloak-bounded-delegation-upstream.md)
for the optional generic policy proposal. No upstream discussion or PR has been
submitted, and no upstream acceptance or maintenance commitment is assumed.

## Existing identity model

An agent is software using an existing `HankoServiceAccount` or
`HankoApplication`. Its resources and scopes belong to a declared
`HankoResourceServer`; its grants use the existing `realm_role`, `application`,
`service_account` and `organization` principals. An organization principal means
the already qualified direct/descendant membership semantics, not a new tenant
identifier inferred from token claims. No agent registry, parallel IAM hierarchy,
SPIFFE identity or agent communication protocol is introduced. Optional task
authorization adds an issuer-controlled signed context and online decision as
described below; default software delegation keeps its existing token shape.

## Optional task authorization in 1.1.0

Set `spec.permissions[].delegation.taskAuthorization: required` for an audience
that requires issuer-controlled task approval. Use `maxDepth: 1`. All delegated
permissions on that audience must use the same mode. The operator probes the
separate strict native task capability before any new grant is applied, and
seals it into plan identity. Missing or incompatible capability refuses the
intent. Omission keeps the existing software-v1 journal bytes and behavior.

The administrator explicitly enables the native task option and binds a trusted
task authority. Native single-use state must use the independently qualified
database topology and matching SDK JAR. This realm setup is not performed by
reconciliation or inferred from a desired task name. The
[task contract](../rfcs/RFC-0002-task-authorization.md) describes the exact API,
authority separation, approved input bindings, cancellation and recipient check.

Task-required journals use wire version 2 and `profile: task-bound-software` in
the existing protected attribute. Legacy parsers refuse that discriminator;
actor guards also prevent an omitted actor from selecting ordinary exchange.
This is an explicit wire guard, not a product profile named “v2”. Native console
components keep their existing domain and refuse externally owned audiences.

The [installed fixture](../../examples/agent-authority/README.md) exercises
separate A2A/MCP/backend audiences, real registration and native token exchange,
and a mandatory online check at MCP before its operation. The recipient
authenticates independently from the actor. The downstream API receives a
separate audience token. Approval is single-use for issuance; business execution
is not an exactly-once distributed transaction. An already admitted operation
can finish concurrently with cancellation; offline JWTs retain residual expiry.

For opt-out or downgrade, withdraw task-required grants, cancel contexts, retain
actor guards and wait the remaining token/context lifetime before changing the
PEP or restoring an older provider/schema. Never reinterpret a remaining task
journal as ordinary delegation. The installed scenario tests withdrawal and
explicit opt-out; clean full-matrix CI and final-image validation remain release
gates. No task material is written to CRD spec/status or controller telemetry.

The **subject** supplies the authority being delegated. The **actor** is the
authenticated software exercising it. The requesting client, actor identity,
subject identity and resource audience are separate inputs; `azp` alone does not
prove an actor. A human subject would require an explicit, qualified consent flow;
the operator never acquires a human password or impersonation permission.

## Reproducible provider evidence

`TestRealKeycloakStandardTokenExchange` runs against both reviewed digest-pinned
images in `versions.json`, over verified TLS 1.3. Tokens are issued by Keycloak
and verified against its HTTPS JWKS with exact issuer, RS256, expiration and
audience checks. Credentials and token bodies remain in fixture memory.

`TestRealKeycloakDelegationPreview` additionally runs a separate **26.8.0-only**
server with `token-exchange-delegation,parameterized-scopes`. It performs a real
authorization-code + PKCE login, native user consent and an FGAP V2 `delegate`
permission. The 26.7.5 cell explicitly skips that unavailable provider; its
standard exchange behavior is still tested. Production configuration never
enables preview features as a consequence of these tests.

| Request / property | 26.7.5 standard and 26.8.0 standard | 26.8.0 delegation preview |
| --- | --- | --- |
| Confidential client with exchange enabled, valid input and configured audience | Accepted; subject retained, requesting client in `azp`, no `act` | Accepted with native `may_act` binding and a valid actor; emits `act` |
| Invalid `actor_token` | Ignored; standard exchange still succeeds | HTTP 400 `invalid_request` |
| Foreign-realm subject / actor | Subject rejected; actor ignored | Foreign actor rejected |
| Public requester / exchange-disabled requester | Rejected | Not separately qualified |
| Requester absent from subject audience | HTTP 403 `access_denied` | Wrong actor binding rejected; complete audience matrix not qualified |
| Unknown / unavailable / disabled target audience | Rejected | Complete audience matrix not separately qualified |
| Optional scope absent from both input tokens | Can be added from requester configuration | Can also be added |
| Composite role outside subject token and actor grants | Can be emitted from subject user's roles plus requester role scopes, even with Full Scope Allowed off | Role intersection not qualified |
| RFC 8693 `resource` parameter | Does not constrain the accepted output | Not separately qualified |
| Declared HankoResourceServer | Not checked: fixture audience is an ordinary OIDC client | Not checked: same ordinary audience client |
| Reuse of subject / actor inputs | Accepted | Accepted |
| Exchange depth | Five successive exchanges accepted without actor history | Six real exchanges build nested `act` without a configured depth bound |
| Expired input | Subject rejected | Actor rejected |
| Output expiration bounded by input expiration | No: exchanged token can outlive short subject token | No: after changing requester lifespan, output can outlive already issued actor token |
| Refresh token from tested transient exchange | Rejected | Rejected |
| Stop future issuance | Disabling client exchange rejects new exchanges | Removing FGAP permission removes `may_act` from newly authorized tokens |
| Revoke an already authorized input | Disabling exchange does not invalidate offline verification of an issued token | Old consented subject remains exchangeable after FGAP permission removal |
| Client administrator adding `may_act` via mapper | Not tested | Accepted without native consent/FGAP validation at exchange time |

The depth experiment deliberately uses administrator-installed `may_act` mappers
after withdrawing FGAP permission. Each input and chained output is genuinely
Keycloak-signed; this characterizes the privilege of a compromised client
administrator, **not** an approved consent mechanism. The first preview scenario
uses native consent without these mappers. Keycloak's optional `may-act` client
policy executor can validate claim issuance, but is not qualified by this lot and
must not be silently assumed to protect the default preview configuration.

The expiration experiments use 20-second disposable input tokens and 120-second
requester lifetimes. They do not change the workload identity lifetime contract.
Offline JWT validation after a configuration change proves residual token
validity only; it makes no claim that token introspection or UMA authorization
has the same revocation behavior.

Run the focused tests locally for each version:

```sh
KEYCLOAK_VERSION=26.7.5 go test -tags=keycloak_integration -race -count=1 -timeout=6m -run '^TestRealKeycloak(StandardTokenExchange|DelegationPreview)$' -v ./internal/controller
KEYCLOAK_VERSION=26.8.1 go test -tags=keycloak_integration -race -count=1 -timeout=6m -run '^TestRealKeycloak(StandardTokenExchange|DelegationPreview)$' -v ./internal/controller
```

The existing `make keycloak-integration-test` and its two-version CI matrix
discover both tests automatically. No additional remote workflow is required for
each local edit.

## Standards and exact versions

[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) defines token exchange,
subject/actor tokens, `act` and `may_act`. Its delegation model does not itself
promise single-use tokens, automatic input/output lifetime coupling, revocation
cascades or a configurable maximum delegation depth. Those are additional
requirements of this operator's proposed authority contract. Historical nested
actors are audit context, not additional authority to union into a grant.

Exact upstream sources accompanying the runtime evidence:

- [26.7.5 standard provider](https://github.com/keycloak/keycloak/blob/44299f39868f252ea02236134618c8c5c70a6e9d/services/src/main/java/org/keycloak/protocol/oidc/tokenexchange/StandardTokenExchangeProvider.java): requester audience checks and requester scope resolution.
- [26.8.0 standard provider](https://github.com/keycloak/keycloak/blob/4246609cf2024c85016d3fb1254c3d2533367c31/services/src/main/java/org/keycloak/protocol/oidc/tokenexchange/StandardTokenExchangeProvider.java): standard exchange rejects delegation-bearing subjects.
- [26.8.0 delegation provider](https://github.com/keycloak/keycloak/blob/4246609cf2024c85016d3fb1254c3d2533367c31/services/src/main/java/org/keycloak/protocol/oidc/tokenexchange/TokenExchangeDelegationProvider.java): actor validation, `may_act` binding and nesting from the actor token's existing `act`.
- [26.8.0 official flow tests](https://github.com/keycloak/keycloak/blob/4246609cf2024c85016d3fb1254c3d2533367c31/tests/base/src/test/java/org/keycloak/tests/oauth/tokenexchange/ClientAgentDelegationTest.java) and [tagged protocol guide](https://github.com/keycloak/keycloak/blob/4246609cf2024c85016d3fb1254c3d2533367c31/docs/guides/securing-apps/token-exchange.adoc): native consent, FGAP and optional `may-act` policy.

## Required authority invariant

For each resource and scope, at issuance **and at the resource enforcement point**:

```text
delegated authority ⊆ actor authority ∩ subject authority ∩ declared grant
output audience ⊆ declared resource-server audience
output expiry ≤ min(subject expiry, actor expiry, now + declared maximum TTL)
chain depth ≤ declared maximum depth
```

The typed intent defaults to one hop, with an explicit maximum of
four, a default maximum TTL of 120 seconds and an absolute maximum of 600 seconds.
These are admission/compiler validation bounds, not provider guarantees.
No native realm/session/assertion lifetime is raised to satisfy them.
An expired or replayed actor token must be refused for new issuance. Revocation
must stop new grants and bound use of already issued tokens by the declared TTL;
immediate revocation may only be advertised with separately proven online resource
enforcement. A local compiler check cannot substitute for token/resource enforcement.

Cross-realm, cross-namespace and cross-tenant references, unowned audiences,
unresolved principals and a missing declared resource server must fail before
provider writes. Composite and inherited roles must be resolved as effective
authority; comparing role names alone is insufficient. An actor cannot select
another human using `requested_subject`. Unsupported provider versions, features
or any unproven invariant require `ErrCapabilityUnsupported`, not a best-effort
exchange or a switch to deprecated legacy exchange.

The stock-provider evidence supplies counterexamples to intersection, replay, depth,
expiry and revocation assumptions. It therefore does **not** authorize a production
delegation capability on either supported version. No custom token broker or
proprietary claims are proposed to conceal these gaps.

## API and ownership decision

| Option | Authority and lifecycle | Decision |
| --- | --- | --- |
| Typed extension of HankoResourceServer permissions | Reuses resources/scopes, existing principal vocabulary, owner UID and one authorization transaction | Preferred when provider enforcement is qualified |
| HankoServiceAccount / HankoApplication fields | Can describe authentication prerequisites but cannot own the target server's grants | Keep identity/authentication there; do not duplicate authorization |
| Dedicated delegation CRD | Adds independent ownership, deletion and cross-controller transactions over the same grants | Unnecessary without an independently justified lifecycle |

`spec.permissions[].delegation` selects `actor` and `subject` with typed
`kind: application|service_account` and namespace-local `ref` fields. Roles and
organizations remain the permission's existing grant principals; they are not
token identities. Human token identities are outside this software-only API.
`maxDepth` and `maxTTLSeconds` bound the permission's explicit declared resources
and scopes, using its ResourceServer's audience and backing Application reference.
No arbitrary client IDs, token templates, mapper JSON or target-realm overrides
are exposed. Omitted delegation preserves existing intent and plan hashes.

The controller validates bounds, different resolved identities, namespace,
realm, tenant, UID and deletion state before checking provider support. Current
profiles report `capabilities.boundedDelegation: false` and a non-secret
`DelegationUnsupported` finding wrapping `ErrCapabilityUnsupported`. No executable
plan, finalizer or provider write is created. Adoption, Observe/import and cleanup
entry points also refuse unsupported delegation; the native conversion cannot
silently turn it into an ordinary permission. Existing applied evidence remains
historical rather than being advanced. Actor/subject and backing application/realm
changes trigger indexed dependency reconciliation.

The native tests additionally compare complete client snapshots and bounded Admin
Event counts across Manage, Observe, import and controller restart. A unit test
asserts zero provider transport calls even if a synthetic plan advertises support.
Admission/defaulting and legacy status compatibility run on all three Kubernetes
versions. Runtime delegation writes and their durable transaction remain
unimplemented until provider enforcement is qualified.

Future provider objects must bind their ownership to the ResourceServer UID and
the resolved Application/ServiceAccount UIDs. Observe performs no writes. Managed
changes use the existing Prepared/Applied/Verified/Committed journal, strict
ownership conflicts, dependency freshness checks and read-back verification.
Deleting or rolling back one owner must never change another client's grant.
Version, enabled features and required enforcement capabilities belong in plan
identity; stale capability evidence invalidates a plan before execution.

## Permissions and public evidence

The real standard tests qualify target-realm `manage-clients` for the exchange
switch, client lifetime, audience mapper CRUD, client-scope CRUD and optional-scope
attachment. `view-clients` and a no-role account cannot alter the exchange switch;
the reader cannot delete a mapper. The writer cannot alter target/master realm
security, create users or impersonate. These native roles are still realm-wide.
The preview mapper experiment demonstrates why `manage-clients` is a trust root,
not an isolation boundary between mutually hostile CRD authors.

Enabling preview features, enabling FGAP and provisioning its `delegate` policy
are external-administrator fixture prerequisites. No production grant is widened
to `manage-realm`; least-privilege FGAP administration and `may-act` client-policy
management are unqualified. The complete operation impact is recorded in the
[administrative permission contract](../keycloak-permissions.md#delegation-characterization).

Public status/journal evidence may contain owner/reference UIDs, generation,
provider version and feature profile, public audience/resource/scope references,
bounds, capability reason codes and non-secret plan identity. It must exclude
tokens, token hashes, credentials, authorization codes, raw actor chains, human
identifiers and membership snapshots. Test evidence likewise records named
assertions and outcomes, never complete token responses or private claims.

## Implementation qualification boundary

[#69](https://github.com/Alien6-Studio/hankoshell-operator/issues/69) must preserve
the unsupported capability result until provider enforcement is proven;
[#70](https://github.com/Alien6-Studio/hankoshell-operator/issues/70) owns the
intersection/depth/TTL proof, including composite escalation and replay negatives.
[#71](https://github.com/Alien6-Studio/hankoshell-operator/issues/71) then requires
installed Pod-to-resource proof and recovery/ownership isolation on Kubernetes
1.35.0, 1.36.2 and 1.37.0 × Keycloak 26.7.5 and 26.8.1. The installed audit above
records all six installed CI cells and six operator-HA CI cells. Direct provider tests remain a separate layer;
neither result closes the RFC's protected integration/review gates.
