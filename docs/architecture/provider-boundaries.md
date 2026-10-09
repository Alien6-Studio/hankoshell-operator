# Portable IAM and provider-native boundaries

This classification resolves [RFC #23](https://github.com/Alien6-Studio/hankoshell-operator/issues/23).
It describes current fields; it does not rename or remove the v1alpha1 API.

- **A — Portable intent:** meaning independent of a particular provider.
- **B — Capability-dependent intent:** meaningful across providers, but support,
  mapping and qualification must be evaluated explicitly.
- **C — Provider-native:** intentionally retained Keycloak configuration.
- **D — Operational/platform:** Kubernetes execution, lifecycle or external integration.

A portable concept is not a promise that another provider implements it. A field
may express portable meaning while its current concrete controls remain native.
Standard metadata, references and status carry D lifecycle/evidence semantics;
they never turn an observation into write authority.

## Current field inventory

Field groups below are exhaustive for current specs, including nested structures.
All current status fields are D observations (IDs, hashes, timestamps, conditions,
counts, resolved endpoints and projection references); they are not portable intent.
Secret references are D operational inputs; their values are excluded from contracts.

| Resource / nested type | Fields | Class / interpretation |
| --- | --- | --- |
| HankoResourceServer | realmRef, applicationRef, audience, displayName | A identity/relationships |
| HankoResourceServer | scopes (name, description), resources (name, displayName, scopes), permissions (name, resources, scopes, principals.kind/ref) | A graph; B evaluation of scope grants, resource objects and principal kinds |
| HankoResourceServer.resources | uris, type | B provider matching/type semantics |
| HankoResourceServer | mode | D local Observe/Manage authority |
| HankoRole | realmRef, name, description | A role identity |
| HankoRole | composite, composites | B additive realm-role composition |
| HankoRole | attributes | C Keycloak metadata lists; ownership key is operator-reserved |
| HankoApplication | realmRef, clientID, type, redirectURIs, postLogoutRedirectURIs | A OIDC application intent; B concrete flow/logout support |
| HankoApplication | protocol, saml (assertionConsumerServices, requireSignedAssertions, nameIDFormat) | A application/SP identity and requirements; B qualified POST/signature/NameID mapping |
| HankoApplication | roles (name, description), realmRoleScopes | A role definitions/bindings; B token scope behavior |
| HankoApplication | theme, attributes | C login theme/client native attributes |
| HankoApplication | mode, secretRotationPolicy, clientSecretProjections (namespace, name) | D authority/credential lifecycle/projection |
| ApplicationIdentityMapping | name, identityProvider, claim, matchValue, target.realmRole/clientRole/userAttribute | B broker claim mapping semantics |
| ApplicationIdentityMapping | keycloakName, syncMode | C mapper names/synchronization |
| ApplicationTokenClaim | name, claim, userAttribute, value, realmRoles, realmRolePrefix, jsonType, multivalued, addToIDToken/addToAccessToken/addToUserInfo/addToIntrospection | B claim meaning/delivery; fixed values are public claim content, never credentials |
| ApplicationTokenClaim | keycloakName | C native mapper naming |
| HankoServiceAccount | realmRef, clientID, scopes | A machine identity; B OAuth scope behavior |
| HankoServiceAccount | tokenClaims | B, same ApplicationTokenClaim classification |
| HankoServiceAccount | attributes | C native client attributes |
| HankoServiceAccount | secretRotationPolicy | D credential lifecycle |
| SecretRotationPolicy | enabled, intervalDays, forceRotateAt | D lifecycle triggers |
| HankoRealm | displayName, roles.name/description | A identity-domain and role meaning |
| HankoRealm.roles | composites | B additive realm-role relationships |
| HankoRealm | otpRequired, iamProfileRef, securityProfile | B authentication policy/profile composition (nested inventory below) |
| HankoRealm | frontendURL, loginTheme | C Keycloak URLs/theme configuration |
| HankoRealm | identityProviders | C broker representation (nested inventory below) |
| HankoRealm.email | providerRef, fromName, replyTo, replyToName | D deprecated API messaging route; not operator SMTP delivery |
| HankoIAMProfile | security | B policy with explicit native mappings below |
| RealmSecurityProfile | mfaPolicy, passwordMinLength, passwordExpiryDays, passwordHistory, passwordRequireUppercase/Lowercase/Digit/Special, passwordDisallowUsername/Email | B policy semantics, currently mapped to Keycloak controls |
| RealmSecurityProfile | bruteForce.enabled/maxFailures/waitIncrements, sessionLifetime, sessionIdleTimeout, emailVerificationRequired, rememberMeEnabled, userRegistrationEnabled | B authentication/session capabilities |
| RealmSecurityProfile | sslRequired, revokeRefreshToken, refreshTokenMaxReuse, otpAlgorithm, otpDigits, otpPeriodSeconds | C concrete Keycloak realm/token/TOTP controls; realm SSL policy does not configure Admin API transport |
| RealmSecurityProfile | userEventsEnabled, adminEventsEnabled, auditRetentionDays, auditExportEnabled, adminConsoleExposure | D audit/exposure policy with C Keycloak listeners/console mapping |
| RealmSecurityProfile | clientSecretRotationDays | D credential lifecycle |
| RealmSecurityProfile | idpBrokerRequireSignature, idpBrokerTrustEmail | B broker security requirements |
| RealmIdentityProvider | alias, providerID, displayName, enabled, trustEmail, storeToken, addReadTokenRoleOnCreate, linkOnly, firstBrokerLoginFlowAlias, postBrokerLoginFlowAlias, config | C explicit Keycloak broker configuration; trust constraints cannot weaken portable policy |
| RealmIdentityProvider | clientSecretRef | D secret injection; no credential import/export |
| RealmIdentityProviderMapper | name, identityProviderMapper, config | C native implementation/configuration, under reserved-authority guards |
| HankoOrganization | realmRef, name, slug, parentRef, roles, clientRoles.client/roles | A hierarchy/role relationships; B provider mapping |
| HankoOrganization | domains, identityProvider | B domain/broker relationships implemented as root native Keycloak Organizations |
| HankoOrganization status | groupID/path, orgID, positionID, observedGeneration, phase/conditions/timestamps | D provider observations and API projection; readiness still coupled until #28 |
| HankoKeycloakInstance | mode, adminRef, tlsCARef, hardenMasterRealm, rotateAdminCredentials, managed, adopted | D provider runtime/administrative opt-ins |
| ManagedKeycloakSpec | tlsSecretRef, allowInsecureHTTP, image, replicas, database, themePVC, resources | D Kubernetes workload/transport/image/credential control |
| AdoptedKeycloakSpec | deploymentRef, serviceRef, publishDiscovery | D explicit workload discovery opt-in |
| HankoImport | sourceRef, realms, includeClients, includeServiceAccounts, includeIdentityProviders, dryRun | D selective discovery/import; generated objects stay Observe/read-only |
| HankoOperation | type, instanceRef, snapshotBefore, upgrade.toImage, clone.targetName/targetNamespace/includeData, dbSwitch.newDatabaseSecretRef, dryRun | D experimental unqualified lifecycle orchestration |
| HankoSnapshot | all spec fields/nested storage configuration | D snapshot scheduling/export/database workload and secret references; no portable recovery guarantee |
| HankoTheme | all spec fields/nested build/source configuration | D Keycloak runtime/theme build and distribution |
| HankoIssuer | host, realmRef | D external issuer/ingress configuration |
| HankoTenant | all spec fields/nested Hub, Keycloak, enforcement, rotation and transport configuration | D enrollment, bundle synchronization, supervision, optional fleet integration |
| HankoMeshService | all spec fields/nested ports/egress | D workload/Service identity resolution and external Continuum audit-only projection |
| HankoEmailProvider | type, enabled, fromAddress, fromName, office365 (tenantID, clientID, mailbox, keyVaultSecretName, preflightRecipient), testNonce | D deprecated platform messaging configuration |

Operational resources marked “all fields” do not hide a portable IAM subset:
their complete spec is deliberately outside the IAM compiler. Kubernetes workload
substructures remain Kubernetes APIs, not generic provider configuration.

## Native extension rule

**Provider-native configuration may extend portable intent, but must not silently
contradict or weaken portable security semantics.** Native PKCE attributes cannot
disable a portable PKCE requirement; broker/native authentication settings cannot
weaken required MFA/signature validation; native token settings cannot contradict
a portable audience requirement. Those application/profile mappings retain their
existing security validations; applications now use their dedicated qualified domain adapter; profile migration
remains later work.

In the migrated role domain, native attributes cannot set `hanko.sh/role-owner`
or credential-shaped keys. The compiler refuses the conflict before any provider
write. Authorization has no arbitrary native payload input: allow-only permissions
and the existing explicit capabilities remain its boundary. Observed native
policies remain unmanaged and cannot become an adoption request implicitly.

Typed, versioned native extensions are preferred when migration needs a new API.
An arbitrary JSON escape hatch is not the default. Existing maps stay available
as their current explicitly classified Keycloak configuration; no schema move is
performed here. Extension validation must preserve local transport, authority,
least-privilege and ownership controls and update permission tests for new calls.

## Staged migration and standalone/projection contract

1. Resource-server authorization and realm roles use internal domain plans; #27
   completed their bounded public evidence and stale-status contract.
2. #28 completed provider-ready standalone organization state, separate optional
   API projection status and provider-first cleanup.
3. #24 adds the [application identity domain](application-identity.md), preserving
   existing OIDC fields and qualifying SAML POST identity/signatures/ACS. Native
   SAML/security/ownership attributes are reserved; migration requires reviewed
   UUID + observation approval. #25 runtime bindings remain next.
4. Realm policy/brokers and operational resources migrate selectively, without a
   blanket generic engine rewrite. Native controls remain first-class Keycloak
   functionality; operational APIs may remain alpha beyond the stable IAM core.

Hub and Continuum remain optional external integrations; this boundary does not
alter their implementation or protocols. No new plan payload is exported. A
second provider belongs to the later portability preview, with explicit semantic
findings rather than parity assumptions. See the
[engine contract and qualification](iam-contract-engine.md).
