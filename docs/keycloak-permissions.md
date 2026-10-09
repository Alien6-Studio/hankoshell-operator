# Keycloak administrative permissions

This is the permission contract for **hankoShell Operator 0.2.0**, verified against
real Keycloak **26.8.0 and 26.7.5** over verified HTTPS with `client_credentials`.
It covers the Admin REST API used by the operator. Kubernetes permissions and
Hub/Continuum credentials are separate; see [secure deployment](secure-deployment.md).

## Trust model

The operator is a privileged identity controller. Anyone allowed to submit
managed CRDs can exercise its Keycloak authority. Keycloak's built-in roles apply
to an entire realm, not to Kubernetes namespaces or the operator's ownership
markers. Ownership checks prevent accidental adoption/deletion; they do not
contain a compromised operator or mutually hostile CRD authors.

`manage-clients` can read and rotate every client secret in its realm, alter token
claims and manage resource-server authorization. `manage-realm` can change security
policy, delete the realm and manage native organizations. These are real residual
powers of the minimum built-in-role profile. Use separate realms and identities
when those powers cross a trust boundary. A fine-grained administration policy
might reduce individual resource scope, but is **not qualified by this contract**.

In 0.2.0 the credential client authenticates in **master**. Target-realm authority
is granted through Keycloak's native **`<target-realm>-realm` client in master**.
These client roles administer that target; they are not master administrative
roles. Do not substitute master `admin` or the `master-realm` client roles.
A realm-local credential client is not supported by the current token endpoint.

Keycloak can expose reduced realm metadata to a master identity without full
access to that realm. Do not interpret HTTP 200 from `GET /admin/realms/{realm}`
as proof of write authority. Verify an intended operation and denied operations.

## Dedicated service account

An administrator provisions one confidential OIDC client in master per operator
trust boundary. Enable service accounts and `client_credentials`; disable standard
flow, direct access grants, implicit flow and public-client mode. Keep **Full Scope
Allowed off**. Assign only the target client's roles listed below to the service
account user, and include those same roles in the credential client's permitted
role scopes. Effective token roles are the intersection of user mappings and
client scopes, including composites and inherited group roles.

Provision the credential through your secret manager into an existing Kubernetes
Secret. For the chart's default connection, set `keycloak.url` and reference
`keycloak.credentialsSecret` with keys `client-id` and `client-secret`.
An instance `spec.adminRef` (or tenant connection Secret) instead uses
`HANKO_KEYCLOAK_URL`, `HANKO_KC_CLIENT_ID` and `HANKO_KC_CLIENT_SECRET`.
Reference a CA Secret separately when needed.
No client secret belongs in a CRD, Helm values committed to Git, or a sample manifest.

The operator checks pre-provisioned access. It **does not create master proxy
clients, administrative roles or role grants**, and a 403 is not repaired by
self-elevation. Keycloak creates/removes its native proxy as part of realm lifecycle.
Upgrading from 0.1.0 does not revoke existing excessive
grants automatically: an administrator must review and remove them.

## Permission and capability matrix

All target roles below belong to `<target-realm>-realm` in master. Management
roles already authorize the corresponding reads; redundant `view-*` and
`query-*` grants are not needed for the tested management profiles.

| Operator capability | Required Keycloak permission | Scope | Optional |
| --- | --- | --- | --- |
| Server discovery and accessible realm inventory | Any administrative role; `view-realm` for full target representation | Granted target realms; restricted version visibility below | No extra role |
| Existing realm configuration, IAM/password/brute-force/session policy and TOTP required-action defaults | `manage-realm` | Each managed target realm | Common profile |
| Realm roles and composite realm roles | `manage-realm` | Each managed target realm | Common profile |
| Event/audit configuration, including default realm reconciliation | `manage-events` | Each managed target realm | Common profile |
| Applications, client roles, protocol mappers and realm-role client scopes | `manage-clients` plus `manage-realm` for realm-role reconciliation/closure | All clients in each target realm | Common profile |
| Machine/service-account clients, secret read/set/rotation | `manage-clients` | All clients in each target realm | Included in common profile; no `manage-users` needed just to create a machine client |
| Resource-server enablement, scopes/resources, role/client policies and scope permissions | Common profile's `manage-clients`; referenced realm roles need `view-realm` or `manage-realm` | All resource servers in target realm | No additional `manage-authorization` role needed |
| Identity providers, broker trust settings and IdP mappers | `manage-identity-providers` | All providers in target realm | Yes |
| Organization hierarchy projected as groups, group attributes and role mappings | `manage-users` plus readable referenced roles (`view-realm`, `view-clients`, already covered by the common profile) | Groups/users throughout target realm | Yes |
| Native Keycloak organizations | `manage-realm` already suffices; isolated organization administration can use `manage-organizations` | Target realm; enabling organizations separately needs `manage-realm` | No extra role on common profile |
| Native organization broker links | Organization management above plus `manage-identity-providers` | Target organizations and brokers | Yes |
| Force realm-wide session revocation when strengthening MFA | `manage-users` | All user sessions in target realm | Required for that security transition |
| Read-only import and realm/application/role/service-account/IdP observation | `view-realm`, `view-clients`, `view-identity-providers` for requested inventory | Each observed target realm | Alternative read-only profile |
| Read-only group observation / authorization observation | Add `view-users` / `view-authorization` to appropriate read profile | Target realm | Separate optional read surfaces |
| Create new realms | Master realm role `create-realm`; native scoped creator grants, described below | Server-wide realm creation; authority over newly created realms | Yes; excluded from common profile |
| Harden master security policy | `manage-realm` of **`master-realm`** | Master security policy | Only with `spec.hardenMasterRealm: true` |
| Automatic rotation of the operator's own master client credential | `manage-clients` of **`master-realm`** | All master clients | Only with `spec.rotateAdminCredentials: true`; prefer administrator-controlled rotation |

The operator does not provision user passwords, user membership or invitations,
perform user impersonation, manage SMTP delivery, or manage administrative role
bindings. Machine-client service accounts use client configuration and credentials;
there is no service-account-user role-mapping API in normal reconciliation.

### Version-dependent read authority

With target-scoped master credentials, `/admin/serverinfo` succeeds on both tested
versions. **Both versions omit `systemInfo.version`** without master realm management;
`status.keycloakVersion` can therefore be empty. An unprivileged service account
is denied discovery on both.
Do not grant master management simply to populate a diagnostic field.
**26.7.5 also allows `view-clients` to read real client secrets**, while 26.8.0
requires `manage-clients`. The suite verifies the returned value against the real
secret without printing it, and rejects secret rotation for the read account on
both versions. On 26.7.5, the built-in-role import profile is read-only for writes
but **is not a credential-confidential identity**. Use 26.8.0 for the tested secret
read boundary, or separately qualify a finer administration policy; do not assume
a `view-*` role excludes secrets. Import/Observe still omits credentials from CRDs,
logs, events and Kubernetes Secrets on both versions.

Instance reconciliation does not attempt master hardening or administrative
credential rotation unless the spec enables them, in every provider mode.
`MasterRealmHardened=False` with reason `NotRequested` means the administrator
owns that baseline. Requested hardening must succeed before the instance becomes
Ready; denied authority leaves it Degraded. Extra roles on the service account
do not enable either operation.

## Minimal profile for an existing Keycloak

Pre-provision the realm and its native Keycloak proxy. Assign exactly:

- `<target-realm>-realm/manage-realm`
- `<target-realm>-realm/manage-clients`
- `<target-realm>-realm/manage-events`

Repeat these grants only for explicitly authorized target realms. This profile
reconciles realm configuration, applications, realm/client roles, protocol mappers,
machine clients and their credentials, and resource-server authorization. It
cannot create new realms, change master, manage target users/groups or brokers,
or impersonate users. It can delete a managed target realm and all its contents:
review finalizers and backups before authorizing realm deletion.

Default realm reconciliation writes event configuration, so `manage-events` is
required even if you did not declare an audit customization. Enabling stronger MFA
can trigger realm-wide logout: grant `manage-users` when that transition is used,
or have an administrator perform the transition and session revocation first.
Never silently skip a denied security action to obtain a green reconciliation.

## Optional authority and new realm creation

Add only the optional capability roles from the matrix. Read-only imports should
use a separate identity and the three `view-*` roles, not the write profile.
The real suite runs the import and Observe reconcilers under that read-only account.

For dynamic realm creation, Keycloak's `create-realm` grants the creator **20
administrative client roles in each new realm** on both qualified versions:
`create-client`, the `view-*` roles for realm/users/clients/events/identity providers/
authorization/organizations, the corresponding `manage-*` roles, and
`query-users`, `query-clients`, `query-realms`, `query-groups`, `query-organizations`.
This includes user and organization management even when the operator does not
need them. It does not grant master `admin`, `realm-admin` or `impersonation`.

New role IDs cannot be pre-scoped before the realm exists. The isolated creator
fixture uses Full Scope Allowed so those native grants reach a refreshed token;
the normal reconciliation accounts keep it off. This optional creator profile is
**broader than the recommended existing-realm profile** and can create arbitrarily
many realms. Prefer out-of-band realm provisioning. If dynamic creation is required,
use a separate installation/identity, review native grants after creation, replace
full scope with the exact role scopes, and remove `create-realm` when provisioning
is finished. The operator never silently grants itself master authority to make
this work.

Master hardening and automatic self-credential rotation require authority on
master itself. There is no qualified mechanism here limiting that client role to
one master setting or one master client. Keep these privileges out of the common
profile and use an administrator or separately constrained external rotation
process. These optional operations are not a justification for global `admin`.

## Permissions that should not be granted

Do **not** grant master `admin`, `realm-admin`, `impersonation`, roles for unrelated
realms, group/composite bindings that inherit these powers, or master user/role
management. Do not grant `create-realm` for pre-existing-realm installations.
Avoid redundant `create-client`, `query-*`, `view-events` and `manage-authorization`
on the common write profile. Omit `manage-users` and `manage-identity-providers`
unless the corresponding capabilities are used.

`realm-admin` aggregates authority far beyond realm/application/role reconciliation,
including users, federation and other administrative surfaces. Giving it as a
default hides permission errors and expands the impact of credential theft and
malicious CRDs. Three reviewed built-in roles are the verified common profile;
each still has the residual realm-wide powers explained in the trust model.

## Credential rotation

Keep the operator credential separate from the application and machine credentials
it manages. Rotate the master service-client secret through an administrator or
external secret manager; synchronize the existing Kubernetes Secret, then restart
or reconcile the clients that loaded it. Verify authentication with the new
credential, retire the previous secret, and audit the transition without logging
secret values or tokens. Exercise failure/recovery in a non-production realm.

Application and `HankoServiceAccount` credential rotation needs only target
`manage-clients`. Instance `AdminRef` credentials are externally managed by
default. `spec.rotateAdminCredentials: true` enables automatic rotation of the
master service-client secret after `HANKO_KC_SA_MAX_AGE` (90 days by default).
This requires master `manage-clients` and the configured metadata audit endpoint;
it is broader authority than application rotation. The chart's default
connection does not require an instance resource.
Only automatic rotation uses the Secret's `hanko.sh/sa-rotated-at` clock.
Disabling it clears the status schedule and stops provider/Secret writes.
If a pending credential exists, reconciliation reports `RotationNotRequested`:
resolve the pending transaction manually or explicitly re-enable rotation.
It does not discard, promote or replay the pending credential without permission.
Administrators using external rotation must enforce their own credential-age policy.
Rotation can update the provider and Secret before audit delivery succeeds;
an audit failure reports a degraded state, not a rollback of the secret change.
Secret rotation alone does not guarantee revocation of already issued bearer tokens.

**Migration:** instances previously attempted these operations automatically.
Apply the new CRD before upgrading and enable the corresponding spec fields only
where the operator should own them. Keep both disabled for ordinary existing
Keycloak installations. Adopting a Kubernetes Service also needs
`spec.adopted.publishDiscovery: true` before its discovery metadata is patched.

## Revocation and incident response

An administrator should disable the compromised credential client, revoke its
sessions/credentials, remove its direct and inherited administrative grants, and
apply the appropriate client/user/realm not-before controls. Verify that a fresh
token cannot be issued and a previously issued token can no longer call the Admin
API; otherwise contain access until its lifetime expires. Use short administrative
access-token lifetimes and a rehearsed revocation procedure.

Stop the affected operator, restrict network access, preserve Keycloak admin events
and Kubernetes audit records, and inspect all clients/policies in every authorized
realm. Rotate secrets the identity could read or change, including machine/client
and broker credentials. Master authority or `create-realm` expands that inspection
scope. Restore/review provider state independently: rolling back the operator does
not undo deleted realms or secret rotations.

## Verify effective configuration

1. With an administrator, inspect the master client's service-account role mappings,
   groups/composites and permitted role scopes. Expand effective roles; check that
   every administrative role belongs to an authorized `<target>-realm` client.
2. In a disposable realm, authenticate using the actual operator client with
   `client_credentials` over verified HTTPS. Never print/store the returned bearer
   token in Git, CI output, issue bodies or screenshots.
3. Exercise the desired realm update, client/role reconciliation, event settings
   and optional features. Test omitted-role failures and denials on master,
   unrelated realms, users, federation, creation and impersonation as applicable.
   A reduced GET response or successful token request is not sufficient evidence.
4. Inspect admin events and operator conditions. Observe/import must produce no
   write events and no credential Secrets. Re-check grants after provisioning,
   Keycloak upgrades, group/composite changes and incident-response exercises.

Reproduce the required CI qualification (Docker required):

```sh
make keycloak-integration-test KEYCLOAK_VERSION=26.8.0
make keycloak-integration-test KEYCLOAK_VERSION=26.7.5
```

The bootstrap administrator only prepares fixtures, injects drift/unowned objects
and verifies state. Normal reconcilers use five target roles (common three plus
`manage-users` for MFA/session enforcement and `manage-identity-providers` for
federation). Import/Observe uses the three read roles. Capability tests use the
common profile and isolated optional identities; removing each common role must
cause an actual HTTP 403. Normal profiles exclude master management, global `admin`, `realm-admin`,
`impersonation` and unrelated realm authority. Separate isolated accounts test
master `manage-realm` for hardening and master `manage-clients` for own credential
rotation, including denials of the other capability. The separate
realm-creator test proves the native broad scoped grant and lack of master access.

These are administrative-operation tests, not end-user authorization/login tests,
production database/cluster tests or proof of fine-grained admin-policy support.
See the [qualification limits](secure-deployment.md#keycloak-compatibility).
The observed differences are consistent with the official client-secret checks
in [26.7.5](https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/services/resources/admin/ClientResource.java)
and [26.8.0](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/services/resources/admin/ClientResource.java),
and native [creator grants](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/services/resources/admin/RealmsAdminResource.java).
Real CI assertions, not documentation alone, define the qualified contract.

## Complete Admin API operation inventory

The reviewed runtime gateway in [permissions.go](../internal/keycloak/permissions.go)
rejects unknown HTTP methods/routes before sending them and refuses redirects.
Configure the canonical Keycloak URL. A syntax-based regression
check rejects direct network calls outside that gateway, including new Go files.
A documentation regression compares this inventory with the executable catalog.
New operations therefore require an explicit contract/documentation change and
must still pass both real-Keycloak permission profiles in required CI. Placeholders
match one escaped path segment; `{path...}` is the group hierarchy path.
The only non-Admin call is `POST /realms/master/protocol/openid-connect/token`
using the dedicated client's credentials.

<!-- admin-operation-contract:start -->
| Capability | Methods | Admin API path | Permission |
| --- | --- | --- | --- |
| discovery | GET | `/admin/serverinfo` | any administrative role; version visibility is version-dependent |
| realms | GET | `/admin/realms` | view-realm (each target; filtered representations) |
| realm-creation | POST | `/admin/realms` | master realm role create-realm; native creator grants |
| realms | GET | `/admin/realms/{realm}` | view-realm or manage-realm |
| realms | PUT,DELETE | `/admin/realms/{realm}` | manage-realm |
| sessions | POST | `/admin/realms/{realm}/logout-all` | manage-users |
| realm-policy | GET,PUT | `/admin/realms/{realm}/authentication/required-actions/CONFIGURE_TOTP` | view-realm / manage-realm |
| events | PUT | `/admin/realms/{realm}/events/config` | manage-events |
| realm-roles | GET,POST | `/admin/realms/{realm}/roles` | view-realm / manage-realm |
| realm-roles | GET,PUT,DELETE | `/admin/realms/{realm}/roles/{role}` | view-realm / manage-realm |
| realm-roles | GET,POST | `/admin/realms/{realm}/roles/{role}/composites` | view-realm / manage-realm |
| realm-roles | GET | `/admin/realms/{realm}/roles/{role}/composites/realm` | view-realm or manage-realm |
| clients | GET,POST | `/admin/realms/{realm}/clients` | view-clients / manage-clients |
| clients | GET,PUT,DELETE | `/admin/realms/{realm}/clients/{client}` | view-clients / manage-clients |
| credentials | GET | `/admin/realms/{realm}/clients/{client}/client-secret` | 26.8.0: manage-clients; 26.7.5: view-clients also exposes secrets |
| credentials | POST | `/admin/realms/{realm}/clients/{client}/client-secret` | manage-clients |
| client-roles | GET,POST | `/admin/realms/{realm}/clients/{client}/roles` | view-clients / manage-clients |
| client-roles | GET,DELETE | `/admin/realms/{realm}/clients/{client}/roles/{role}` | view-clients / manage-clients |
| client-roles | GET | `/admin/realms/{realm}/clients/{client}/roles/{role}/composites` | view-clients |
| client-scopes | GET,POST,DELETE | `/admin/realms/{realm}/clients/{client}/scope-mappings/realm` | view-clients / manage-clients and permission to map the realm role |
| protocol-mappers | GET,POST | `/admin/realms/{realm}/clients/{client}/protocol-mappers/models` | view-clients / manage-clients |
| protocol-mappers | PUT,DELETE | `/admin/realms/{realm}/clients/{client}/protocol-mappers/models/{mapper}` | manage-clients |
| identity-providers | GET,POST | `/admin/realms/{realm}/identity-provider/instances` | view-identity-providers / manage-identity-providers |
| identity-providers | PUT,DELETE | `/admin/realms/{realm}/identity-provider/instances/{alias}` | manage-identity-providers |
| identity-provider-mappers | GET,POST | `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers` | view-identity-providers / manage-identity-providers |
| identity-provider-mappers | PUT,DELETE | `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{mapper}` | manage-identity-providers |
| groups | GET | `/admin/realms/{realm}/group-by-path/{path...}` | view-users or manage-users |
| groups | POST | `/admin/realms/{realm}/groups` | manage-users |
| groups | GET,PUT,DELETE | `/admin/realms/{realm}/groups/{group}` | view-users / manage-users |
| groups | GET,POST | `/admin/realms/{realm}/groups/{group}/children` | view-users / manage-users |
| group-roles | GET | `/admin/realms/{realm}/groups/{group}/role-mappings` | view-users |
| group-roles | GET,POST | `/admin/realms/{realm}/groups/{group}/role-mappings/realm` | view-users / manage-users and permission to map the realm role |
| group-roles | GET,POST | `/admin/realms/{realm}/groups/{group}/role-mappings/clients/{client}` | view-users / manage-users and permission to map the client role |
| organizations | GET,POST | `/admin/realms/{realm}/organizations` | view-organizations / manage-organizations or manage-realm |
| organizations | GET,PUT,DELETE | `/admin/realms/{realm}/organizations/{organization}` | view-organizations / manage-organizations or manage-realm |
| organization-idps | GET,POST | `/admin/realms/{realm}/organizations/{organization}/identity-providers` | view-organizations / manage-organizations (or manage-realm) and manage-identity-providers |
| organization-idps | DELETE | `/admin/realms/{realm}/organizations/{organization}/identity-providers/{alias}` | manage-organizations (or manage-realm) and manage-identity-providers |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/scope` | view-authorization / manage-authorization or manage-clients |
| authorization | PUT,DELETE | `/admin/realms/{realm}/clients/{client}/authz/resource-server/scope/{object}` | manage-authorization or manage-clients |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/resource` | view-authorization / manage-authorization or manage-clients |
| authorization | PUT,DELETE | `/admin/realms/{realm}/clients/{client}/authz/resource-server/resource/{object}` | manage-authorization or manage-clients |
| authorization | GET | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/{object}/associatedPolicies` | view-authorization or manage-authorization or manage-clients |
| authorization | GET | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy` | view-authorization or manage-authorization or manage-clients |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/role` | view-authorization / manage-authorization or manage-clients |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/client` | view-authorization / manage-authorization or manage-clients |
| authorization | PUT | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/role/{object}` | manage-authorization or manage-clients |
| authorization | PUT | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/client/{object}` | manage-authorization or manage-clients |
| authorization | DELETE | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/{object}` | manage-authorization or manage-clients |
| authorization | GET | `/admin/realms/{realm}/clients/{client}/authz/resource-server/permission` | view-authorization or manage-authorization or manage-clients |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/scope` | view-authorization / manage-authorization or manage-clients |
| authorization | PUT | `/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/scope/{object}` | manage-authorization or manage-clients |
| authorization | DELETE | `/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/{object}` | manage-authorization or manage-clients |
<!-- admin-operation-contract:end -->


The 0.2 adapter qualification reads scope permissions with `fields=*` on the
existing collection route, and reads their associated policy IDs through the
explicitly inventoried `GET .../policy/{object}/associatedPolicies`. These are
bounded read operations under the existing target permissions. Real tests prove
common-profile success, read-only success and unprivileged HTTP 403; no new
administrative role is granted. They are needed for semantic idempotence because
Keycloak's default permission lists omit these relationships.
