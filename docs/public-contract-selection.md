# Initial public IAM contract selection

This review selects a **candidate stable API contract** for #81, its frozen
semantics in #82 and its reusable fixtures in #84. The operator was published as
[v1.0.0](https://github.com/Alien6-Studio/hankoshell-operator/releases/tag/v1.0.0)
with experimental APIs. Its publication does not activate this stable contract.
The selection and graduation reviews may expand the surface after the required
evidence is available.

<!-- public-selection:start -->

Initial selection: 3 candidate public resource contracts. Operator v1.0.0 is published; all current APIs remain experimental pending a separate graduation decision.

| Resource | Selected scope | Public spec groups |
| --- | --- | --- |
| `HankoApplication` | public | `clientID`, `mode`, `postLogoutRedirectURIs`, `protocol`, `realmRef`, `realmRoleScopes`, `redirectURIs`, `roles`, `saml`, `type`, `webOrigins` |
| `HankoEmailProvider` | experimental | — |
| `HankoIAMProfile` | alpha | — |
| `HankoImport` | experimental | — |
| `HankoIssuer` | alpha | — |
| `HankoKeycloakInstance` | experimental | — |
| `HankoMeshService` | experimental | — |
| `HankoOperation` | experimental | — |
| `HankoOrganization` | alpha | — |
| `HankoRealm` | alpha | — |
| `HankoResourceServer` | public | `applicationRef`, `audience`, `displayName`, `mode`, `permissions`, `realmRef`, `resources`, `scopes` |
| `HankoRole` | public | `composite`, `composites`, `description`, `mode`, `name`, `realmRef` |
| `HankoServiceAccount` | alpha | — |
| `HankoSnapshot` | experimental | — |
| `HankoTenant` | experimental | — |
| `HankoTheme` | experimental | — |
| `HankoWorkloadTrust` | alpha | — |

Native SAML and CORS entry policy remain Keycloak extensions. Delegation, organization principals,
connected integrations and every other deferred field retain their named limitations in
the complete selection; no planned capability is removed.

<!-- public-selection:end -->

## Complete field review

[public-contract-selection.json](../tools/qualification/config/contracts/public-contract-selection.json) assigns public,
alpha or experimental status to every one of the 353 top-level spec/status field
groups in all 17 resources. A group includes its nested fields except the explicit
`nestedExclusions`. Every row has a rationale and repository evidence. The
selection gate rejects missing/new groups, undeclared native boundaries, missing
evidence and drift in README/chart summaries. The [development support inventory](api-support.md)
continues to describe present maturity independently of this future selection.

The selected domains have explicit sealed compilers, separate portable intent and
execution identities, UID ownership and fail-closed adoption. Their existing unit,
real API, real HTTPS Keycloak and installed-system fixtures provide the basis for
selection. These are laboratory and application-example observations; no public
production deployment or second-provider equivalence is claimed. Representative
use is the OIDC/SAML application, additive role and UMA resource-server scenarios
in `examples/` and the installed system corpus. Public production evidence remains
#88; a future graduation decision cannot substitute this corpus for real reports.

`HankoApplication` selects OIDC client configuration, role scopes and native SAML.
SAML is an explicit Keycloak extension, qualified only in the pinned window;
public classification never means provider parity. Native attributes, claim/IdP
mappers, themes, credential projections, rotation and runtime binding fields remain
alpha. `HankoRole` selects additive realm-role semantics; arbitrary native
attribute metadata remains alpha. `HankoResourceServer` selects the allow-only
resource/scope/principal graph. Organization principal extensions remain alpha;
bounded delegation remains experimental and unsupported, including when nested
inside an otherwise selected permission. Public status groups are bounded
observation/evaluation evidence, never an authority grant or raw provider payload.

## Deferred capability decisions

Realm/profile, organization, service-account/workload and issuer behavior remains
available as alpha. Their full defaulting, plan and cross-release contracts have
not been selected; domain-specific native extensions and version limits continue
to apply. Application declarations can use an existing Keycloak realm without a
managed Realm CR, so selecting these three domains does not promise managed
realm/instance lifecycle compatibility.

Instance/import/snapshot/operation/theme workflows, deprecated email delivery and
connected tenant/mesh APIs remain experimental. Hub/Continuum delivery, signed
Fleet and workload qualification retain their actual installed boundaries, rather
than implying a public connected service contract. Upgrade/DBSwitch, managed-source
Clone, portable database restore, traffic enforcement and cloud/CNI/CSI support
remain unqualified where already documented.

Stock Keycloak's bounded delegation counterexamples remain explicit. The
[dedicated extension and installed qualification](architecture/delegation-and-agent-identity.md)
provide the experimental implementation; they do not graduate this field group.
#72–#75 qualify an experimental second adapter and the shared installed corpus;
a second production adapter has not been delivered. Promoting a deferred field
group requires qualified implementation, a selection update, fixtures and migration
review.

## Compatibility and rollback

The candidate contract covers the selected field groups and documented execution
meaning, including capability refusal and UID ownership. It is not a 1.0 SemVer,
provider parity or cross-release guarantee. See the [migration policy](api-migration-policy.md)
for stored `v1alpha1`, CRD ordering, journal readability and condition topology.
The initial v1.0.0 had no earlier public predecessor. A fixture against one
development image must not be described as N-1 public-release rollback.
Subsequent releases must use authentic published artifacts for those checks.
