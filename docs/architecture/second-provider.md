# Experimental second provider decision

Decision for [#72](https://github.com/Alien6-Studio/hankoshell-operator/issues/72),
reviewed on 2026-10-16. The selected implementation target is **authentik
2026.8.4**, pinned to the official server image index
`sha256:e7226ae116dac5aa0a5643803e735b010038f492c401e08e16b3bf1ac54c090c`.
The qualification window contains this exact version only. It is experimental;
no production support or feature parity is promised.

## Candidate comparison

The comparison uses exact-version upstream source, rather than assuming that an
OIDC/SAML feature implies an equivalent management contract.

| Candidate | Standards and administration | Contract differences | Decision |
| --- | --- | --- | --- |
| [authentik 2026.8.4](https://github.com/goauthentik/authentik/releases/tag/version/2026.8.4) | REST `/api/v3`; configurable OIDC client IDs, strict redirect registrations, public/confidential clients, SAML, groups, RBAC and service identities. Core source is MIT; enterprise functionality is separately licensed. Real self-hosted server with PostgreSQL is available for CI. | Authentication flows, scope mappings and signing keys are administrator prerequisites. Groups are not realm roles, application access policies are not resource-server grants, and service-account token authentication must not implicitly provision a user. | Selected for a narrow, executable OIDC SPA/web migration experiment. Other domains are explicitly unsupported by this adapter. |
| [Logto 1.45.0](https://github.com/logto-io/logto/releases/tag/v1.45.0) | Management REST API, OIDC applications, API resources/scopes, roles, organizations and machine clients. MPL-2.0 core; real container/PostgreSQL fixture available. | Its application creation API generates the OIDC client ID. A Hanko `clientID` cannot silently become a display name. API resources/scopes alone do not implement resource-instance grants or composite realm roles. SAML integration does not establish the exact Hanko SP/signature contract. | Rejected for this first migration: preserving the declared client identity is the principal lossless requirement. |
| [ZITADEL 4.19.5](https://github.com/zitadel/zitadel/releases/tag/v4.19.5) | Versioned protobuf/gRPC/HTTP APIs, OIDC/SAML/API applications, projects, organizations, project roles, service accounts and token exchange. Real PostgreSQL fixture available. The exact tag's AGPL-3.0 licensing requires review before distribution. | Project roles are not additive realm-role composites; generated application/client identities and project/organization references require explicit migration. Resource-instance authorization and bounded delegation are not established by protocol support. | Rejected for this bounded experiment: broader organizational/application mapping would precede the intended identical-client migration. |

| Domain | authentik | Logto | ZITADEL |
| --- | --- | --- | --- |
| OIDC | Configurable client ID and redirect registrations; selected bounded mapping. | Generated client ID prevents the selected identical-client migration. | Generated client/project identity requires migration mapping. |
| SAML | Native SP provider exists; Hanko signing/ACS contract remains unqualified. | SSO integration is not evidence of the selected SP contract; unqualified. | Native application definitions exist; Hanko signing/ACS contract remains unqualified. |
| Roles/groups | Native groups and administrative RBAC are not realm-role composites. | Roles exist; additive realm-role composition is unqualified. | Project roles exist; additive realm-role composition is unqualified. |
| Resource server | Application/policy controls are not resource-instance grants. | API resources/scopes are not the complete Hanko resource/principal graph. | Project/application roles are not the complete Hanko resource/principal graph. |
| Service accounts | Native service users exist; implicit user provisioning is refused. | Native M2M application model exists; client identity difference requires review. | Native machine users exist; identity/application mapping requires review. |
| Workload federation | Native JWT federation fields exist; Kubernetes anchor/age/rotation semantics unqualified. | Kubernetes trust semantics are not established by the reviewed routes. | Kubernetes trust semantics are not established by the reviewed application/project definitions. |
| Token exchange | No qualified bounded delegation contract; refused. | No qualified bounded delegation contract; refused. | Protocol support is not proof of bounded intersection/depth/lifetime/replay; refused. |

Primary exact-version API evidence:

- authentik [OAuth2 provider serializer and filters](https://github.com/goauthentik/authentik/blob/version/2026.8.4/authentik/providers/oauth2/api/providers.py),
  [application API](https://github.com/goauthentik/authentik/blob/version/2026.8.4/authentik/core/api/applications.py),
  [OpenAPI schema](https://github.com/goauthentik/authentik/blob/version/2026.8.4/schema.yml),
  [authorization/PKCE processing](https://github.com/goauthentik/authentik/blob/version/2026.8.4/authentik/providers/oauth2/views/authorize.py),
  [license](https://github.com/goauthentik/authentik/blob/version/2026.8.4/LICENSE).
- Logto [application routes](https://github.com/logto-io/logto/tree/v1.45.0/packages/core/src/routes/applications),
  [schema](https://github.com/logto-io/logto/tree/v1.45.0/packages/schemas/src),
  [license](https://github.com/logto-io/logto/blob/v1.45.0/LICENSE).
- ZITADEL [application v2 definitions](https://github.com/zitadel/zitadel/blob/v4.19.5/proto/zitadel/application/v2/application.proto),
  [project/role definitions](https://github.com/zitadel/zitadel/blob/v4.19.5/proto/zitadel/project.proto),
  [license](https://github.com/zitadel/zitadel/blob/v4.19.5/LICENSE).

## Exact experimental semantics

| Contract domain | authentik mapping / outcome |
| --- | --- |
| Identity domain / realm | Unsupported. A pre-existing authentik installation is a connection prerequisite, not a newly managed HankoRealm. |
| IAM profile | Unsupported. No translation of MFA/session/password policy into flows or arbitrary expressions. |
| OIDC SPA | Public OAuth2 provider plus application; exact client ID, strict HTTPS redirects, authorization-code/refresh grants only, explicit signing key and administrator-provisioned OIDC mappings. |
| OIDC web | Confidential OAuth2 provider with the same bounded registration semantics. Credential delivery is unqualified and `Operational=False`; IAM read-back alone is not application availability. |
| M2M / service account | Unsupported. The adapter must not provision users or convert client identity into user authentication. |
| SAML | Unsupported by this adapter, although the provider implements SAML. Hanko's signing, ACS and NameID semantics have not been qualified here. |
| Roles / composites | Unsupported; no group-as-role downgrade. |
| Organizations | Unsupported; no hierarchy/role-membership approximation. |
| Resource-server grants | Unsupported; application access policies do not establish resource/scope/principal graph equivalence. |
| Workload federation | Unsupported; no claim that native JWT federation satisfies Kubernetes trust/anchor/rotation requirements. |
| Bounded delegation | Unsupported; token exchange alone cannot prove intersection, depth, lifetime coupling or replay guarantees. #69–#71 remain unfinished. |
| Native extensions | Retained on Keycloak; refused by this adapter before a write. No portable-only restriction is added to Keycloak. |

An application also refuses a referenced realm carrying inherited security,
brokers, roles, native settings or other policy. A present realm must select the
same connection; its presence/absence and version enter execution freshness.
The adapter cannot bypass MFA or other inherited policy by retargeting a child.

Post-logout destinations, client/realm role bindings, claims, identity mappers,
themes, rotation and Kubernetes credential/runtime projections are also refused
on the experimental adapter. An empty set cannot silently become an unmanaged
scope selection. Every omission in this table is an unsupported outcome, not a
loss accepted by default.

## Connection, authority and recovery

The connection is a same-namespace administrator-owned ConfigMap containing one
`connection.json` document with strict `authentik.Connection` fields. The explicit
`hanko.sh/provider-connection` label selects it. This typed metadata extension
avoids renaming the existing Keycloak API or adding provider-native fields to the
candidate public spec. The process and chart opt-in are disabled by default. The process also requires
an explicit connection-name allow-list. The enabled chart installs a fail-closed
ValidatingAdmissionPolicy protecting those exact ConfigMap names in the release
namespace for CREATE/UPDATE/DELETE. Only `system:masters` or explicitly configured
administrator groups may change them; ordinary ConfigMap writers and the operator
are refused. Administrators review existing objects before enabling their names.
Raw binary installations must install equivalent independent protection first.
Other IAM domains carrying the selector must refuse before falling through to
the default Keycloak client. Removing the opt-in with existing objects retains
cleanup finalizers and reports disabled execution.

The execution plan additionally binds a canonical non-secret connection identity,
including origin, flow IDs, signing key and OIDC scope mappings. A sealed plan
cannot be reused with another connection configuration.

Connections pin the exact provider/version, bare HTTPS origin, logical realm,
credential Secret, optional private CA Secret, authorization/invalidation flow
UUIDs, signing-key UUID and OIDC scope-mapping UUIDs. Credential Secrets contain
`token`; CA Secrets contain `ca.crt`. No credential value is accepted in the
ConfigMap. TLS verification, fixed origin, redirect refusal, method/route
allow-list, response byte budget, timeouts and typed status errors are mandatory.

The durable non-secret application journal binds the source UID, connection UID,
provider origin and logical client. Provider/application ownership markers bind
the source UID **and provider origin**. Cross-provider retargeting, foreign
same-named objects and unknown journal versions are refused. A prepared local
checkpoint precedes provider creation. Recovery finds the exact owned provider
by client ID, then its bound application; lost acknowledgement never authorizes
an unmarked object. Deletion verifies absence before releasing the finalizer.
These checks are not a distributed compare-and-swap transaction with authentik;
concurrent provider-administrator mutation remains a trust boundary.

## Reproducible fixture and permissions

Use the real pinned server and a disposable PostgreSQL database, isolated from
production. Bootstrap may create flows, a signing key, OIDC mappings and the
operator service principal. Runtime credentials have only `view/add/change/delete`
for `oauth2provider` and `application`. The adapter cannot create users, tokens,
flows, keys, scope mappings, policies or RBAC grants. A credential without these
permissions must fail with a bounded typed failure. The fixture terminates TLS
at a private, verified test edge; its backend HTTP port is loopback-only. No
insecure production transport escape hatch exists in the adapter.

The representative migration is the same `portable-v1` SPA/web declaration
executed independently on Keycloak and authentik. Each provider creates its own
native objects; neither provider adopts the other's ownership marker. This
proves registration intent and recovery, not user/password migration, session
continuity, credential projection or provider parity.

The data corpus is `internal/iamconformance/testdata/portable-v1/corpus.json`.
Every domain declares lossless/unsupported classification and evidence per
provider. **Portable intent hashes must agree; execution-plan hashes must differ**
when backend or local authority changes. Comparing the complete PlanIdentity
including backend would contradict the existing execution-authority contract.
No lossy fixture is accepted in this first corpus.

This RFC proceeds independently of the unresolved native delegation experiment:
its unsupported finding is part of the second-provider contract. Neither this
selection nor the adapter closes #69–#71. Installed matrix qualification belongs
to #75; source/API tests and a mocked provider are not installed-system evidence.

## Run the current gates

`make authentik-integration-test` starts a fresh pinned server/database, seeds
only disposable prerequisites, runs the fourteen-fixture real-server suite with
`-race`, preserves bounded JUnit/outcome JSON and deletes its containers/network.
Private bootstrap data and credentials stay in a mode-0600 temporary directory.
The real adapter gate is mandatory in the CI source job. `make integration-test`
also validates every fixture manifest and proves the connection policy denies a
ConfigMap writer while allowing an independent administrator.

The corpus currently has in-memory identity/classification checks and complete
real authentik execution/refusal coverage. Connecting every literal fixture to
the real Keycloak suite (including installed Kubernetes workload trust bindings)
is remaining work in #73. The six-cell installed two-provider matrix is remaining
work in #75. Existing independent Keycloak suites remain mandatory.
