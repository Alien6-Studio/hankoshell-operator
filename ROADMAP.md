# hankoShell Operator Roadmap

## Direction

hankoShell Operator is an open-source Kubernetes execution plane for IAM.
Application identity, authentication and authorization requirements belong beside
deployment configuration, as desired state that the operator validates,
reconciles and observes. **Keycloak is the first and currently only implemented
IAM backend.**

The direction is a provider-neutral IAM contract with explicit provider
capabilities and plans. Deep Keycloak configuration remains part of the product:
portable concepts and provider-native extensions have different contracts, and
neither should silently change the other's semantics.
The portable Hanko IAM model and Keycloak implementation depth evolve together;
provider abstraction must not postpone useful Keycloak capabilities.

The target architecture is:

```text
Hanko IAM Contract → Capability Resolution → IAM Plan → Provider Adapter → Provider APIs
                                                        ├─ Keycloak
                                                        └─ future provider
```

This extends the existing [authorization driver](internal/authorization/driver.go)
and [HankoResourceServer](api/v1alpha1/hankoresourceserver_types.go), which already
separate desired authorization, capabilities, owned provider references and
findings. Other portable resources can adopt these patterns where useful;
operational resources need not share an identical schema.

Standalone Kubernetes/GitOps operation remains a complete use case. Optional
hankoShell Hub integration adds distributed desired-state coordination and
bounded status. **Continuum is an external, separately versioned implementation.**
Work here concerns Operator ↔ Continuum configuration, connectivity contracts,
bounded policy projection and health reporting. Its networking, WireGuard,
node transport, packet enforcement and mesh runtime stay outside this repository.

The [official Keycloak Operator](https://www.keycloak.org/operator/basic-deployment)
manages Keycloak deployment and runtime lifecycle. hankoShell Operator complements
it with declarative IAM configuration; it also supports existing installations
and its own explicit managed-instance mode. Provider workload ownership and IAM
ownership remain separate.

## Current status

**Target public release: 0.1.0. Current status: development.** Active technical
metadata is `0.1.0-dev.0`; no public release has been published yet.
Phases 1–5 supply the implemented foundation, including #54 canonical Attest
identity hardening. Phases 6–10 are required before the first public release;
P6.2 adds independent Kubernetes trust ownership; workload binding and federated
M2M client activation remain subsequent milestones.
All 17 `hanko.sh/v1alpha1` APIs remain experimental.

Phase 2 — IAM Contract Engine, Phase 3 — Application Identity, Phase 4 —
Organizational Authorization and Phase 5 — Adopt Existing Keycloak have completed
source milestones. Phase 1 retains its open milestone because
[#21](https://github.com/Alien6-Studio/hankoshell-operator/issues/21) tracks
transversal first-publication trust and readiness. That evidence also belongs to
Phase 10's exit gate. Phase 4 follows the
[accepted contract](docs/architecture/organizational-authorization.md) in #41/#42;
Phase 5 follows the [adoption contract](docs/architecture/existing-keycloak-adoption.md)
and RFC #46, with #47/#48/#49 delivering discovery/diff, reviewed leaf ownership
and aggregate/native qualification. The accepted target-realm HankoRole
`manage-realm` exception is unchanged. The
[OIDC/SAML application contract](docs/architecture/application-identity.md) and
[UID-bound runtime delivery](docs/architecture/application-identity.md#runtime-bindings)
resolve #24/#25 without another CRD.

The next phase is **Phase 6 — Workload Identity**. It has no independent public
version. The [phase mapping](docs/engineering-milestone-mapping.md) preserves
existing milestone IDs, issue associations and open/closed states.
Phase 6A's [architecture contract](docs/architecture/workload-identity.md) selects
native Keycloak Kubernetes client assertions, independent typed trust ownership
and the existing HankoServiceAccount M2M concept. Local UID containment must be
implemented before federated activation; native authentication does not enforce
SA UIDs or single-use assertions. Subsequent implementation order is trust,
binding/mesh, authentication/migration, then full installed-system qualification.

P6.2 adds the independent seventeenth `HankoWorkloadTrust` CRD, exact provider
ownership/journal, current-cluster anchor/discovery checks, explicit adoption and
shared-age/deletion dependency guards. Its distinct dependent reader has only
target-realm view-clients; on 26.7.5 this credential can expose client secrets,
even though the controller prohibits credential routes. Writer and reader
credentials share the manager process and their practical powers combine on
compromise. Binding/mesh (#61), federated client activation (#62) and complete
installed migration (#63) remain separate implementation work.

The current foundation already includes:

- `HankoRealm` and `HankoIAMProfile`: reusable MFA, password, session, brute-force,
  event and broker-trust configuration, including effective-policy hashes.
- `HankoApplication`, `HankoRole` and `HankoServiceAccount`: OIDC SPA/web/M2M
  clients, realm/client/composite roles, typed claims and broker mappings,
  confidential-client rotation and authorized Secret projections; qualified SAML
  POST applications with signed assertions/responses and exact ACS destinations.
- `HankoResourceServer`: scopes, resources and allow-only permissions for role,
  application and service-account principals, capability status and owned IDs;
  organization principals with explicit declared descendants and bounded provenance.
- `HankoOrganization`: nested groups, realm/client-role mappings and native
  Keycloak Organizations at roots. Standalone `Ready` requires only provider
  synchronization; configured platform projection has its own condition and
  dependency ordering. Provider cleanup precedes optional projection cleanup.
- `HankoImport` and Observe/Manage ownership: supported configuration discovery,
  observation resources and controlled reconciliation. Complete native import
  coverage and a reviewable adoption plan remain future work.
- Explicit provider modes, themes, snapshots and lifecycle operations; optional
  `HankoIssuer`, `HankoTenant` and `HankoMeshService` platform integrations,
  enrollment, credential rotation, supervision and guarded operator updates.

`HankoOperation`'s `Upgrade`, `Clone` and `DBSwitch` workflows are experimental
and unqualified in the current lifecycle contract. Their interruption/retry, child ownership and completion
qualification remains in [lifecycle backlog issue #20](https://github.com/Alien6-Studio/hankoshell-operator/issues/20),
separate from the core IAM phases; Phase 10 must explicitly document their alpha limits. They do not provide a tested
database migration or disaster-recovery path; see the
[lifecycle limits](docs/secure-deployment.md#lifecycle-operation-qualification).
No future release version is assigned to that qualification yet.

Resource-server authorization and realm roles now use a
[local IAM contract foundation](docs/architecture/iam-contract-engine.md): explicit
intent/resolution/capabilities/plans, versioned canonical identities and freshness
checks. Keycloak capability evidence names the static mapping and qualification
window. The external authorization-plan annotation is not execution evidence.
Public evaluated/applied/observation evidence and stale status implement #27 for
roles/authorization and extend to applications in #24. Standalone organization
projection separation completed #28.
No second backend or general portability qualification is implied.

Hub bundles currently use token-derived **HMAC**, without independent publisher
authentication. Ed25519 mesh policy projection is **audit-only**. Cryptographically
verifiable, versioned and replay-resistant IAM plans remain future work; their
mechanism requires an RFC. These are distinct from transport security and the
existing signed release evidence.

Source, real-provider, Kubernetes, installed-system and exact-image delivery
checks already exist. See [qualification and security limits](docs/secure-deployment.md),
[Keycloak permissions](docs/keycloak-permissions.md), [SECURITY.md](SECURITY.md)
and [CHANGELOG.md](CHANGELOG.md). Production delivery configuration, broader
installation qualification and portable database recovery are not implied by
passing those checks. `HankoEmailProvider` is deprecated; platform messaging
belongs to the API.

## Engineering roadmap

Engineering phases are capability and qualification goals for the first public
0.1.0, with no intermediate public versions or arbitrary due dates.
Their descriptions contain scope, existing foundations, non-goals, standalone
and connected impact, success criteria and community questions. Later milestones
will be refined through RFCs and real use; they are not promises of provider parity.

| Engineering phase | Outcome, building on current functionality | Completion evidence |
| --- | --- | --- |
| [Phase 1 — Trusted Keycloak Foundation](https://github.com/Alien6-Studio/hankoshell-operator/milestone/1) | Deliver the trusted Keycloak foundation; production trust/publication is separately tracked in #21. Experimental lifecycle qualification remains separate. | Passing core gates and independently verified production delivery prerequisites. |
| [Phase 2 — IAM Contract Engine](https://github.com/Alien6-Studio/hankoshell-operator/milestone/2) | Extend resource-server capabilities/ownership and IAM-profile hashing into locally validated plans, observations, portability findings and internal Keycloak adapters. Separate optional projection readiness. | Deterministic identity, stale/unsupported-plan rejection, adapter conformance and standalone reconciliation. No second provider. |
| [Phase 3 — Application Identity](https://github.com/Alien6-Studio/hankoshell-operator/milestone/3) | Mature existing OIDC applications into protocol-aware runtime contracts; design and qualify SAML and explicit workload bindings. | Usable metadata/credential references, migration tests and real protocol qualification. |
| [Phase 4 — Organizational Authorization](https://github.com/Alien6-Studio/hankoshell-operator/milestone/4) | Implement the accepted ResourceServer organization principal with explicit descendants, preserving role composition; add bounded effective authorization and provenance. No new CRD. | Grant reconciliation, bounded provenance and real HTTPS/Kubernetes qualification complete. |
| [Phase 5 — Adopt Existing Keycloak](https://github.com/Alien6-Studio/hankoshell-operator/milestone/5) | Consolidate Keycloak configurator coverage into discover → observe → plan → diff → adopt → manage, with typed native findings. Deep Keycloak development continues across milestones. | Selective adoption, no secret export, preservation of foreign objects and native-feature qualification. |
| [Phase 6 — Workload Identity](https://github.com/Alien6-Studio/hankoshell-operator/milestone/6) | Extend service-account clients and mesh identity resolution with qualified Kubernetes identity federation, short-lived authentication and explicit secret fallback. | Real audience/issuer/binding denials; IAM identity remains separate from transport registration. |
| [Phase 7 — Delegation & Agent Identity](https://github.com/Alien6-Studio/hankoshell-operator/milestone/7) | Extend the same principal model with standards-based delegation, token exchange and constrained agent/workload authority. | Depth, audience, lifetime, revocation and capability-intersection tests; no separate agent IAM stack. |
| [Phase 8 — Provider Portability](https://github.com/Alien6-Studio/hankoshell-operator/milestone/8) | Prove representative identical intent with a second experimental adapter while retaining deep Keycloak features. Provider selection remains open. | Shared conformance and explicit lossless/lossy/unsupported differences; no full-parity claim. |
| [Phase 9 — Fleet Reconciliation](https://github.com/Alien6-Studio/hankoshell-operator/milestone/9) | Build on enrollment, supervision and lifecycle guards with cryptographically verifiable, versioned and replay-resistant desired-state plans, capability-aware rollout and bounded fleet evidence. The verification mechanism remains an RFC decision. | Tamper/replay rejection, capability validation, partial rollout, disconnection and safe reconnect under local authority; versioned external integration contracts. |
| [Phase 10 — Initial Public Contract Stabilization](https://github.com/Alien6-Studio/hankoshell-operator/milestone/10) | Qualify the complete first-public scope: explicit portable/native boundaries, versioning/defaulting, conversion and stored-object migration, compatibility/deprecation policy and standalone/connected limits. Select the public IAM core through conformance review and real application use; operational/platform APIs may remain alpha. | Accepted initial-contract review, round-trip/defaulting/ownership/migration tests, reusable portable/native conformance and rollback fixtures, and independently approved first-publication trust in #21. No blanket API graduation or provider-parity promise. |

All ten GitHub milestones use these non-SemVer phase names. Their numbers,
links, issue associations and states remain intact. Phases 2–5 remain closed;
Phase 1 stays open for transversal #21 evidence and Phases 6–10 remain open.
Track progress with milestones, issues/RFCs, temporary branches, PRs, commits
and CI. Do not create development, phase or checkpoint tags.

## Product version and first-public exit criteria

The complete scope previously planned through the old stable-contract goal is
now the maturity path of **0.1.0**, not a later release series. No intermediate
public release will precede it. Before publication, implement and qualify
Workload Identity, Delegation & Agent Identity, Provider Portability and Fleet
Reconciliation, then complete Phase 10's initial contract review and #21's real
trust/publication evidence. Preserve each phase's scope and negative tests.

Review candidates include realm/identity domain, IAM profile, application, role,
organization, resource server, service-account/workload identity and sufficiently
mature entitlement/delegation. Document any deferred surface explicitly; do not
remove an entire planned capability to accelerate publication. Robust first-use
qualification is required, while `v1alpha1` APIs may remain alpha with explicit
limits. Public 0.x does not promise absolute backward compatibility or automatic
promotion of operational/platform resources.

A future **1.0.0** has no current milestone or predetermined roadmap. Decide it
after actual public/production use across the evolving 0.x series, a proven public
contract, an assumed compatibility policy, mature conversions/migrations and an
explicit backward-compatibility commitment. Phase 10 qualifies first publication;
it does not make that later SemVer commitment.

## Design principles

- **Declarative over imperative:** desired state → plan → validate → apply → observe.
- **Local authority:** an operator can refuse unsafe, stale or unsupported state,
  including proposals delivered by Hub.
- **Explicit ownership:** adoption, field management, deletion and cleanup have
  distinct, reviewable boundaries; one writer owns each managed provider object.
- **Secure by default:** transports, credentials, delegated authority and remote
  operations fail closed. Provider credentials stay local and out of status,
  public plans and Hub bundles.
- **Provider-aware portability:** expose lossless, lossy and unsupported behavior;
  never silently weaken intent to fit an adapter.
- **Deep Keycloak support:** provider-native extensions remain available behind
  clear validation, permission and qualification contracts.
- **Keycloak capability evolves continuously:** abstraction must never freeze or
  reduce Keycloak coverage. Each milestone may deepen the adapter for real IAM
  needs: SAML in Phase 3, authorization mappings in Phase 4, adoption coverage in Phase 5 and
  workload federation in Phase 6 are part of that direction.
- **Standalone OSS usefulness:** IAM reconciliation remains useful without Hub,
  the platform API or Continuum; optional projection has its own status.
- **Complementary operators:** keep Keycloak runtime lifecycle separate from IAM
  desired state, including deployments owned by the official Keycloak Operator.
- **Separate Continuum implementation:** integration status and signed policy
  projection do not assert networking or IAM enforcement by this repository.

## Contributing

Bring concrete application authentication, authorization, adoption and workload
identity scenarios to the [roadmap issues](https://github.com/Alien6-Studio/hankoshell-operator/issues?q=is%3Aissue%20is%3Aopen%20label%3Aroadmap).
The next active engineering milestone is **Phase 6 — Workload Identity**, with no public version assigned; production
publication trust is tracked independently in #21. The resolved Phase 2 architecture and selected Phase 3
RFCs guide subsequent development; later milestone
descriptions carry direction until their design window opens.

Start with the RFCs for [provider capabilities and plans](https://github.com/Alien6-Studio/hankoshell-operator/issues/22),
[portable/native boundaries](https://github.com/Alien6-Studio/hankoshell-operator/issues/23),
[OIDC/SAML application protocols](https://github.com/Alien6-Studio/hankoshell-operator/issues/24)
and [runtime application identity bindings](https://github.com/Alien6-Studio/hankoshell-operator/issues/25).
Schemas, adapter boundaries, loss acceptance, binding delivery and the stable
v1 subset remain open to community input. RFC examples are proposals, not
installable API definitions.

Use [CONTRIBUTING.md](CONTRIBUTING.md) for public technical proposals, alternatives,
migration impact and qualification evidence. Report vulnerabilities through
[SECURITY.md](SECURITY.md), rather than public roadmap issues.
