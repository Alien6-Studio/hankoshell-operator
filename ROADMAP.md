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

The active product version is **0.1.0**, the first intended public distribution.
It consolidates the qualified E1–E5 capabilities and #54 release-trust hardening;
there is no rollback to the old foundation-only source. Public tags use
`release/v<SemVer>`, starting with `release/v0.1.0`. No public release tag, package
or GitHub Release is created by source preparation. The earlier 0.5.1 model was
canceled before tagging.

Signed `v0.1.0`, `v0.2.0`, `v0.3.0`, `v0.4.0` and `v0.5.0` are immutable
**historical engineering/source checkpoints**, not five public releases. Their
Git objects and signatures stay fixed. Public `release/v0.1.0` is a distinct ref
on the fully qualified current source, not an alias of historical `v0.1.0`.

E2 — IAM Contract Engine, E3 — Application Identity, E4 — Organizational
Authorization and E5 — Adopt Existing Keycloak have completed source milestones.
E1's existing GitHub milestone remains open for production trust in
[#21](https://github.com/Alien6-Studio/hankoshell-operator/issues/21), separately
from its delivered foundation code. E4 follows the
[accepted contract](docs/architecture/organizational-authorization.md) in #41/#42.
E5 follows the [accepted adoption contract](docs/architecture/existing-keycloak-adoption.md)
and [RFC #46](https://github.com/Alien6-Studio/hankoshell-operator/issues/46), with
[#47](https://github.com/Alien6-Studio/hankoshell-operator/issues/47),
[#48](https://github.com/Alien6-Studio/hankoshell-operator/issues/48) and
[#49](https://github.com/Alien6-Studio/hankoshell-operator/issues/49) supplying
discovery/diff, reviewed ownership and aggregate/native qualification. The
accepted target-realm HankoRole `manage-realm` exception is unchanged.

The next engineering milestone is **E6 — Workload Identity**. No E6 work or
future public version is included in this version-model correction. The
[qualified OIDC/SAML application contract](docs/architecture/application-identity.md)
resolves #24; [UID-bound runtime delivery](docs/architecture/application-identity.md#runtime-bindings)
implements #25 without another CRD. Current chart/app metadata is 0.1.0. All 16
`hanko.sh/v1alpha1` APIs remain experimental during public initial development.
Later engineering milestones describe proposed scope, not current support or a
SemVer release schedule.

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
and unqualified in public 0.1.0. Their interruption/retry, child ownership and completion
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

## Engineering roadmap

Engineering milestones are design and qualification goals, with no assigned public versions or arbitrary due dates.
Their descriptions contain scope, existing foundations, non-goals, standalone
and connected impact, success criteria and community questions. Later milestones
will be refined through RFCs and real use; they are not promises of provider parity.

| Engineering milestone | Outcome, building on current functionality | Completion evidence |
| --- | --- | --- |
| [E1 — Trusted Keycloak Foundation](https://github.com/Alien6-Studio/hankoshell-operator/milestone/1) | Deliver the trusted Keycloak foundation; production trust/publication is separately tracked in #21. Experimental lifecycle qualification remains separate. | Passing core gates and independently verified production delivery prerequisites. |
| [E2 — IAM Contract Engine](https://github.com/Alien6-Studio/hankoshell-operator/milestone/2) | Extend resource-server capabilities/ownership and IAM-profile hashing into locally validated plans, observations, portability findings and internal Keycloak adapters. Separate optional projection readiness. | Deterministic identity, stale/unsupported-plan rejection, adapter conformance and standalone reconciliation. No second provider. |
| [E3 — Application Identity](https://github.com/Alien6-Studio/hankoshell-operator/milestone/3) | Mature existing OIDC applications into protocol-aware runtime contracts; design and qualify SAML and explicit workload bindings. | Usable metadata/credential references, migration tests and real protocol qualification. |
| [E4 — Organizational Authorization](https://github.com/Alien6-Studio/hankoshell-operator/milestone/4) | Implement the accepted ResourceServer organization principal with explicit descendants, preserving role composition; add bounded effective authorization and provenance. No new CRD. | Grant reconciliation, bounded provenance and real HTTPS/Kubernetes qualification complete. |
| [E5 — Adopt Existing Keycloak](https://github.com/Alien6-Studio/hankoshell-operator/milestone/5) | Consolidate Keycloak configurator coverage into discover → observe → plan → diff → adopt → manage, with typed native findings. Deep Keycloak development continues across milestones. | Selective adoption, no secret export, preservation of foreign objects and native-feature qualification. |
| [E6 — Workload Identity](https://github.com/Alien6-Studio/hankoshell-operator/milestone/6) | Extend service-account clients and mesh identity resolution with qualified Kubernetes identity federation, short-lived authentication and explicit secret fallback. | Real audience/issuer/binding denials; IAM identity remains separate from transport registration. |
| [E7 — Delegation & Agent Identity](https://github.com/Alien6-Studio/hankoshell-operator/milestone/7) | Extend the same principal model with standards-based delegation, token exchange and constrained agent/workload authority. | Depth, audience, lifetime, revocation and capability-intersection tests; no separate agent IAM stack. |
| [E8 — Provider Portability Preview](https://github.com/Alien6-Studio/hankoshell-operator/milestone/8) | Prove representative identical intent with a second experimental adapter while retaining deep Keycloak features. Provider selection remains open. | Shared conformance and explicit lossless/lossy/unsupported differences; no full-parity claim. |
| [E9 — Fleet Reconciliation](https://github.com/Alien6-Studio/hankoshell-operator/milestone/9) | Build on enrollment, supervision and lifecycle guards with cryptographically verifiable, versioned and replay-resistant desired-state plans, capability-aware rollout and bounded fleet evidence. The verification mechanism remains an RFC decision. | Tamper/replay rejection, capability validation, partial rollout, disconnection and safe reconnect under local authority; versioned external integration contracts. |

The existing GitHub milestones retain their historical SemVer-shaped titles,
IDs, issue associations, links and open/closed states. The proposed non-destructive
[E1–E9 title mapping](docs/engineering-milestone-mapping.md) is documented; no
GitHub milestone was renamed because dependencies on titles in external/project
automation have not been excluded. The numeric titles mean historical engineering
milestones, not a public release promise.

Track future engineering work through milestones, issues, branches, protected
commits and CI. Do not create bare `vX.Y.Z` tags for development milestones.
A separately reviewed signed source checkpoint can use an explicitly non-release
namespace such as `checkpoint/E6`, which the public release parser rejects.

## Product releases

| Public version | Meaning | Release decision |
| --- | --- | --- |
| 0.1.0 | First public product distribution: all currently qualified E1–E5 capabilities and release-trust hardening. | Source preparation first; signed annotated release/v0.1.0, production trust and publication each require separate authorization. |
| Future 0.x | Product and public compatibility changes during initial development. | Decide the SemVer version when a distribution is reviewed; no E-number-to-version mapping. |
| 1.0.0 | An explicit commitment to a stable public IAM/API contract and compatibility policy. | Only after a stability/graduation review, mature migration/conversion strategy and evidence that the chosen API surface is stable. No date or mechanical milestone count. |

The [existing stability-review milestone](https://github.com/Alien6-Studio/hankoshell-operator/milestone/10)
is a qualification gate, not a tenth-step release calendar. It may occur much
later than the listed engineering work. Likely review candidates are
realm/identity domain, IAM profile, application, role, organization, resource server
and service-account/workload identity. Entitlement/delegation join only if mature.
Resources may remain `v1alpha1` throughout the public 0.x series; promoting all
operational/platform resources is not the goal.

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
  needs: SAML in E3, authorization mappings in E4, adoption coverage in E5 and
  workload federation in E6 are part of that direction.
- **Standalone OSS usefulness:** IAM reconciliation remains useful without Hub,
  the platform API or Continuum; optional projection has its own status.
- **Complementary operators:** keep Keycloak runtime lifecycle separate from IAM
  desired state, including deployments owned by the official Keycloak Operator.
- **Separate Continuum implementation:** integration status and signed policy
  projection do not assert networking or IAM enforcement by this repository.

## Contributing

Bring concrete application authentication, authorization, adoption and workload
identity scenarios to the [roadmap issues](https://github.com/Alien6-Studio/hankoshell-operator/issues?q=is%3Aissue%20is%3Aopen%20label%3Aroadmap).
The next active engineering milestone is **E6 — Workload Identity**, with no public version assigned; production
publication trust is tracked independently in #21. The resolved E2 architecture and selected E3
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
