# Delegation and agent authority

See the [accepted architecture decisions](decisions/README.md) for the underlying
operator, provider and trust boundaries.

This is the provider characterization and authority contract for
[RFC #68](https://github.com/Alien6-Studio/hankoshell-operator/issues/68).
The first implementation of #69 accepts typed intent and refuses unqualified
execution. **Neither supported Keycloak version currently qualifies bounded
delegated authority.** Successful OAuth token exchange alone must not enable that
capability.

## Existing identity model

An agent is software using an existing `HankoServiceAccount` or
`HankoApplication`. Its resources and scopes belong to a declared
`HankoResourceServer`; its grants use the existing `realm_role`, `application`,
`service_account` and `organization` principals. An organization principal means
the already qualified direct/descendant membership semantics, not a new tenant
identifier inferred from token claims. No agent registry, parallel IAM hierarchy,
new token format, SPIFFE identity or agent communication protocol is introduced.

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
KEYCLOAK_VERSION=26.8.0 go test -tags=keycloak_integration -race -count=1 -timeout=6m -run '^TestRealKeycloak(StandardTokenExchange|DelegationPreview)$' -v ./internal/controller
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

The current evidence supplies counterexamples to intersection, replay, depth,
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
1.35.0, 1.36.2 and 1.37.0 × Keycloak 26.7.5 and 26.8.0. The direct provider tests
here do not replace those six installed cells or close the RFC's merge/review gates.
