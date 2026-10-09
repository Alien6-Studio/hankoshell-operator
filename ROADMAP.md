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

The **v0.1.0, v0.2.0, v0.3.0 and v0.4.0 sources and signed tags are frozen and immutable**.
Publication work remains independent in [#21](https://github.com/Alien6-Studio/hankoshell-operator/issues/21);
no public artifacts are claimed published. Milestone **0.2.0 — IAM Contract Engine**
is complete and closed. **0.3.0 — Application Identity** is complete and closed,
including the protocol and runtime delivery contract. **0.4.0 — Organizational
Authorization** is complete and closed, with organization grants and bounded structural provenance
under the [accepted contract](docs/architecture/organizational-authorization.md),
implemented by #41 and #42. Active development is **0.5.0 — Adopt Existing
Keycloak**, starting with the [accepted adoption contract](docs/architecture/existing-keycloak-adoption.md)
and [RFC #46](https://github.com/Alien6-Studio/hankoshell-operator/issues/46).
[#47](https://github.com/Alien6-Studio/hankoshell-operator/issues/47),
[#48](https://github.com/Alien6-Studio/hankoshell-operator/issues/48) and
[#49](https://github.com/Alien6-Studio/hankoshell-operator/issues/49) implement discovery/diff,
explicit ownership and aggregate/native qualification in that order. Current
HankoImport/Observe remains the available inventory behavior until those changes
land; general adoption is not implemented by the RFC. Production publication
remains independent in #21.
[#24](https://github.com/Alien6-Studio/hankoshell-operator/issues/24) is resolved by
the [qualified OIDC/SAML application contract](docs/architecture/application-identity.md).
[#25](https://github.com/Alien6-Studio/hankoshell-operator/issues/25) defines
[UID-bound runtime delivery](docs/architecture/application-identity.md#runtime-bindings),
implemented on HankoApplication without another CRD. Chart/app source metadata is
0.4.0. The 16 `hanko.sh/v1alpha1` APIs remain experimental before 1.0. Later
milestones are proposed scope, not additional current support or scheduled delivery.

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
and unqualified in 0.4.0. Their interruption/retry, child ownership and completion
qualification remains in [lifecycle backlog issue #20](https://github.com/Alien6-Studio/hankoshell-operator/issues/20),
not a prerequisite for the first core IAM delivery. They do not provide a tested
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

## Milestones

Milestones are design and qualification goals, with no arbitrary due dates.
Their descriptions contain scope, existing foundations, non-goals, standalone
and connected impact, success criteria and community questions. Later milestones
will be refined through RFCs and real use; they are not promises of provider parity.

| Milestone | Next outcome, building on current functionality | Completion evidence |
| --- | --- | --- |
| [0.1.0 — Trusted Keycloak Foundation](https://github.com/Alien6-Studio/hankoshell-operator/milestone/1) | Complete trusted first publication of the reviewed IAM core. Experimental lifecycle qualification remains separate, without a scheduled version. | Passing core gates and independently verified production delivery prerequisites. |
| [0.2.0 — IAM Contract Engine](https://github.com/Alien6-Studio/hankoshell-operator/milestone/2) | Extend resource-server capabilities/ownership and IAM-profile hashing into locally validated plans, observations, portability findings and internal Keycloak adapters. Separate optional projection readiness. | Deterministic identity, stale/unsupported-plan rejection, adapter conformance and standalone reconciliation. No second provider. |
| [0.3.0 — Application Identity](https://github.com/Alien6-Studio/hankoshell-operator/milestone/3) | Mature existing OIDC applications into protocol-aware runtime contracts; design and qualify SAML and explicit workload bindings. | Usable metadata/credential references, migration tests and real protocol qualification. |
| [0.4.0 — Organizational Authorization](https://github.com/Alien6-Studio/hankoshell-operator/milestone/4) | Implement the accepted ResourceServer organization principal with explicit descendants, preserving role composition; add bounded effective authorization and provenance. No new CRD. | Grant reconciliation, bounded provenance and real HTTPS/Kubernetes qualification complete. |
| [0.5.0 — Adopt Existing Keycloak](https://github.com/Alien6-Studio/hankoshell-operator/milestone/5) | Consolidate Keycloak configurator coverage into discover → observe → plan → diff → adopt → manage, with typed native findings. Deep Keycloak development continues across milestones. | Selective adoption, no secret export, preservation of foreign objects and native-feature qualification. |
| [0.6.0 — Workload Identity](https://github.com/Alien6-Studio/hankoshell-operator/milestone/6) | Extend service-account clients and mesh identity resolution with qualified Kubernetes identity federation, short-lived authentication and explicit secret fallback. | Real audience/issuer/binding denials; IAM identity remains separate from transport registration. |
| [0.7.0 — Delegation & Agent Identity](https://github.com/Alien6-Studio/hankoshell-operator/milestone/7) | Extend the same principal model with standards-based delegation, token exchange and constrained agent/workload authority. | Depth, audience, lifetime, revocation and capability-intersection tests; no separate agent IAM stack. |
| [0.8.0 — Provider Portability Preview](https://github.com/Alien6-Studio/hankoshell-operator/milestone/8) | Prove representative identical intent with a second experimental adapter while retaining deep Keycloak features. Provider selection remains open. | Shared conformance and explicit lossless/lossy/unsupported differences; no full-parity claim. |
| [0.9.0 — Fleet Reconciliation](https://github.com/Alien6-Studio/hankoshell-operator/milestone/9) | Build on enrollment, supervision and lifecycle guards with cryptographically verifiable, versioned and replay-resistant desired-state plans, capability-aware rollout and bounded fleet evidence. The verification mechanism remains an RFC decision. | Tamper/replay rejection, capability validation, partial rollout, disconnection and safe reconnect under local authority; versioned external integration contracts. |
| [1.0.0 — Stable Hanko IAM Contract](https://github.com/Alien6-Studio/hankoshell-operator/milestone/10) | Stabilize the proven portable IAM core, with explicit native boundaries, conversions and compatibility guarantees. | Accepted API graduation review, conversion/migration tests and public conformance fixtures. Operational/platform resources may remain alpha. |

For 1.0, likely review candidates are realm/identity domain, IAM profile,
application, role, organization, resource server and service-account/workload
identity. Entitlement and delegation primitives join only if mature enough.
Promoting all current `v1alpha1` resources is not the goal.

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
  needs: SAML in 0.3, authorization mappings in 0.4, adoption coverage in 0.5 and
  workload federation in 0.6 are part of that direction.
- **Standalone OSS usefulness:** IAM reconciliation remains useful without Hub,
  the platform API or Continuum; optional projection has its own status.
- **Complementary operators:** keep Keycloak runtime lifecycle separate from IAM
  desired state, including deployments owned by the official Keycloak Operator.
- **Separate Continuum implementation:** integration status and signed policy
  projection do not assert networking or IAM enforcement by this repository.

## Contributing

Bring concrete application authentication, authorization, adoption and workload
identity scenarios to the [roadmap issues](https://github.com/Alien6-Studio/hankoshell-operator/issues?q=is%3Aissue%20is%3Aopen%20label%3Aroadmap).
The active development milestone is 0.5.0 — Adopt Existing Keycloak; production
publication trust is tracked independently in #21. The resolved 0.2 architecture and selected 0.3
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
