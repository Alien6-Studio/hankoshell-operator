# Application identity: OIDC and SAML

This resolves [RFC #24](https://github.com/Alien6-Studio/hankoshell-operator/issues/24)
in the **0.3.0 — Unreleased** source development. The signed v0.2.0 boundary is
unchanged; chart/app/release packaging stays 0.2.0 until milestone 0.3 completes.
The `hanko.sh/v1alpha1` API is experimental. A future graduated API may group OIDC
fields differently. Keycloak is the only implemented backend.

## Public contract

`spec.protocol` is `oidc` or `saml`; omission defaults to `oidc`. Existing OIDC
fields stay at their current paths. SPA, confidential web and M2M clients retain
callbacks, logout redirects, themes, client roles, declared realm-role scopes,
token claims, inbound OIDC broker mappings, native client attributes, credential
rotation and authorized Secret projections. Manage and Observe remain separate.

```yaml
apiVersion: hanko.sh/v1alpha1
kind: HankoApplication
metadata:
  name: finance-portal
  namespace: auth
spec:
  realmRef: enterprise
  clientID: https://finance.example.com/saml
  protocol: saml
  saml:
    assertionConsumerServices:
      - https://finance.example.com/saml/acs
    requireSignedAssertions: true
    nameIDFormat: persistent
  roles:
    - name: use
      description: Use the finance portal
```

For SAML, **clientID is the SP entity ID**. Real Keycloak uses `clientId` to match
the AuthnRequest issuer; a second independent `entityID` would create ambiguous
identity. An absolute URI of at most 255 characters is required. ACS destinations
are an exact set of 1–8 HTTPS URLs, each at most 2048 characters, using DNS or IPv4
host syntax. No HTTP opt-in, wildcard, userinfo, query or fragment is supported.
The first destination in canonical sorted order is Keycloak's default POST ACS;
requests can select another registered exact destination.

`requireSignedAssertions` defaults to true and cannot be false. Both assertions
and responses are signed. `nameIDFormat` defaults to `persistent`; qualified values
are `persistent`, `transient`, `email` and `unspecified`. The IdP forces that format
independently of the request preference. Email uses the SAML 1.1 emailAddress URI;
unspecified uses the SAML 1.1 unspecified URI and Keycloak's username mapping.

SAML rejects `type`, OIDC callbacks/logout redirects, `tokenClaims`,
`identityMappings`, even an explicitly empty `realmRoleScopes`, rotation policies
and client-secret projections. Client roles and login theme selection are shared
semantics. A realm's inherited OIDC rotation policy does not create a SAML secret.

## Plan and adapter boundary

```text
HankoApplication → applications.Intent → resolved references + capabilities
                 → sealed local Plan → KeycloakDriver → observation
```

`internal/applications` defines the domain; `internal/iamcontract` supplies the
existing version, digests, findings, plan identity and preconditions. There is no
global provider interface, remote executable plan or new public Plan resource.
The controller resolves Kubernetes references, mode, authority and secret access.
The adapter maps provider protocols, client representations, ownership,
observations and protocol metadata. Existing OIDC child reconciliations retain
their authorization guards and use independent adapter read-back.

Explicit normalized intent includes protocol, identity, pattern, callbacks,
roles, claims, broker requirements, theme and non-secret credential requirements.
Native mappings and local authority enter the provider plan separately. Neither
whole CRs, status nor Secret contents enter canonical hashes. Sealed-plan JSON
emits identity only. Equivalent set ordering, omitted OIDC/defaults, empty mapper
audience/role prefix and qualified provider defaults normalize consistently.
Generated provider IDs and secret-creation timestamps do not define semantic state.

Freshness checks re-read the application UID/generation, realm/rotation
dependencies, theme identity/readiness, mode/provider-selection labels, migration
approval and provider endpoint identity before mutation batches. Projection
preconditions read Secret metadata only, bind its UID and recheck local
authorization. The provider client UID/protocol is independently checked before
child/credential execution and deletion. Keycloak has no conditional client-write
transaction: the final read and PUT are separate, and multi-resource execution
can partially complete. Administrators must avoid concurrent ownership edits.

## Qualified Keycloak mapping

Qualification is static adapter evidence from **26.7.5 and 26.8.0**, not privileged
runtime capability discovery. No global `admin`, `realm-admin` or impersonation
grant is required. The protocol/client/client-role suite uses only target-realm
`manage-clients`. Declared realm-role scope writes additionally require
`manage-realm`; optional brokers retain `manage-identity-providers`. Public
discovery/metadata reads carry no administrative bearer token and use the existing
verified TLS/CA transport and 1 MiB response budget. See [permissions](../keycloak-permissions.md).

| Portable requirement | Qualified Keycloak representation |
| --- | --- |
| OIDC | `protocol=openid-connect`; SPA public, web confidential, M2M service account; direct grants/implicit flow/full scope disabled |
| SAML entity | `protocol=saml`, `clientId` equals SP entity URI |
| Exact ACS set | `redirectUris`, plus `saml_assertion_consumer_url_post` for the canonical first ACS |
| Signed response | `saml.server.signature=true` |
| Signed assertion | `saml.assertion.signature=true` |
| Signature algorithm | `saml.signature.algorithm=RSA_SHA256`, exclusive XML canonicalization |
| Unsigned SP request | `saml.client.signature=false` |
| POST response | `saml.force.post.binding=true` |
| NameID | `saml_name_id_format`, `saml_force_name_id_format=true` |
| Unsupported alternatives | Encryption, artifact binding and ECP disabled |
| Application ownership | Client attribute `hanko.sh/application-owner` equals CR UID |
| Mapper deletion authority | Fresh mapper config UID marker plus independently owned client; status IDs only locate candidates |

Native `attributes` remain a full-map escape hatch for client attributes outside
managed settings. `saml*`, `hanko.*`, `hanko.sh/*`, protocol, theme, logout and
credential-shaped keys are reserved and rejected. Native extensions cannot
override signing, ACS or ownership. Sibling resource-server authorization state
and its ownership journal are preserved by client updates.

## Ownership and 0.2 migration

New clients carry the HankoApplication UID. A client carrying another nonempty UID
cannot be adopted, updated, used to retrieve credentials or deleted. A matching
clientID or forged status hash is insufficient. Protocol conflicts are explicit:
`ProtocolMismatch` for observation/foreign objects and
`ProtocolChangeRequiresRecreation` for an owned client.

The 0.2 client markers (`hanko.app`/`hanko.service`) did not bind a Kubernetes UID.
**Upgrading such an installation requires explicit administrator migration
approval**, including for a SPA without a Secret. The manifest's omitted protocol
still means OIDC; it does not itself prove ownership.

1. Reconcile the existing declaration. `OwnershipApprovalRequired` exposes a
   fresh, non-secret `status.observedStateHash` without provider mutations or
   credential retrieval. Review the declared desired fields and actual client,
   roles and mappers independently through an administrator account.
2. Obtain the **exact Keycloak client UUID** through that independent account.
   Set both annotations on the existing declaration:
   `hanko.sh/migrate-keycloak-client-uuid` and
   `hanko.sh/migrate-keycloak-observation` (the reviewed observation hash).
   Do not copy an unreviewed hash merely to clear the conflict.
3. Reconcile. The adapter freshly checks UUID, complete observation, protocol and
   absence of a foreign UID, then stamps ownership and reconciles declared state.
   Stale or mismatched approval is refused; status is never execution authority.
4. Verify Ready, applied/read-back evidence, original UUID/roles/mapper UUIDs and
   existing credentials. Remove the migration annotations after adoption.

Migration preserves UUIDs, roles, mapper identities and current confidential
credentials when desired semantics are unchanged. Declared mappers receive a UID
config marker without recreation. Old undeclared realm-scoped broker mappers
without that marker cannot be safely identified for deletion and require manual
review/cleanup. An already-due explicit rotation policy can still rotate a secret;
upgrade/adoption itself does not request rotation.

**Protocol conversion is not supported in place**, in either direction. Real
Keycloak permits a protocol PUT while retaining incompatible old fields; the
operator refuses it. Export/review the old configuration and application impact,
delete the owned HankoApplication and wait for finalizer/provider cleanup, then
create the new declaration. This changes provider UUID and may invalidate roles,
credentials, sessions or consumers. Reverting YAML is not provider recovery.

## Status and operational semantics

OIDC retains `status.oidcEndpoints`; SAML clears it and exposes
`status.samlEndpoints`: realm issuer/entity ID, POST SSO URL, metadata URL and
response binding. The realm metadata supplies public signing certificates and
rollover keys; neither full XML nor private signing keys enter status.
`HankoRealm.spec.frontendURL` determines public identity/endpoints when configured.
The private administrative URL is not substituted into public metadata.

`Synced/Ready` proves supported provider configuration. `Operational` separately
reports bounded discovery/metadata validation through the configured trusted CA;
it does not prove every production login or application-side SP configuration.
OIDC reads discovery; SAML reads only its descriptor. Reconciliation failure or protocol mismatch
clears endpoint claims. On OIDC discovery failure, declared public endpoints remain
with Operational=false; they do not prove reachability. Observe reports actual protocol, observations and
findings without writes, credential reads, Secrets, applied proof or finalizers.

Evidence follows the 0.2 contract: contract/backend/protocol, intent and evaluated
plan hashes/generation, last proven applied plan/generation, observation hash and
plan/generation, completeness/drift, bounded capabilities and findings. An error
does not turn evaluation into application. Status is evidence, never authority.
SAML/unknown imports report bounded unsupported/read-only findings and do not
generate misleading OIDC resources. Use a reviewed explicit Observe declaration.

## Protocol and XML security qualification

The real-Keycloak suite runs a disposable authenticated user through SP-initiated
unsigned AuthnRequest and validates the resulting POST Response and Assertion.
The synthetic SP uses checksum-locked Go modules `goxmldsig` 1.6.1 and `etree` 1.7.0;
cryptographic XMLDSig verification is delegated to that library, not handwritten.
These are test dependencies: the operator does not accept SAML login responses.

The fixture consumes only verified signed elements and checks exact issuer,
audience, destination, recipient, request correlation, status, NameID and validity.
Both signatures must use RSA-SHA256/SHA256 and the qualified exclusive
canonicalization/transforms. Public TLS-authenticated metadata supplies the real
signing certificate. Wrong ACS/audience/request, expiry, tampering, duplicate
assertions and algorithm downgrade are rejected. XML limits are 1 MiB, depth 32
and 4096 elements; DTDs/entities, processing instructions, ambiguous/duplicate IDs,
duplicate attributes and multiple roots are refused before tree allocation.

The OIDC fixture verifies browser authorization code/state/nonce with PKCE,
registered redirect rejection, issuer/audience and a managed fixed claim; SPA
CORS/no Secret and M2M client credentials are also qualified. Existing OIDC
Admin API regression, rotation, broker mappings and Secret projection tests stay
in CI. Kubernetes 1.35.0/1.36.2/1.37.0 qualify admission/defaults/status plus the
existing RBAC/Restricted boundaries. The exact scanned-image system fixture on
1.37.0/26.8.0 qualifies installed OIDC/SAML reconciliation, UID ownership,
protocol status, no SAML credential, Observe and deletion; protocol handshakes
are qualified separately in the two-version Keycloak suite.

Unsigned AuthnRequests do not authenticate the SP. Exact ACS and signed responses
do not make an application safe if its SP ignores signature, audience, recipient,
correlation or timestamp checks. The application must validate those properties
and manage certificate rollover. TLS-authenticated metadata retrieval is not an
independent XML metadata signature verification.

Unsupported: SLO, signed SP requests/certificate trust, encrypted assertions,
artifact/ECP flows, IdP-initiated login, typed SAML attribute statements,
certificate pin distribution, external IdP handshakes and production database or
network acceptance. [#25](https://github.com/Alien6-Studio/hankoshell-operator/issues/25)
will define runtime identity bindings/metadata delivery; no binding resource,
ConfigMap delivery or live Hub application plan is introduced here.

Provider references: [Keycloak SAML administration](https://www.keycloak.org/docs/latest/server_admin/index.html#_saml_clients),
[qualified 26.8.0 SAML attributes](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/protocol/saml/SamlConfigAttributes.java),
[XMLDSig test library](https://github.com/russellhaering/goxmldsig).
