# Keycloak administrative permissions

This is the permission contract for **hankoShell Operator 0.5.0**, verified against
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

In 0.5.0 the credential client authenticates in **master**. Target-realm authority
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

Runtime bindings add **no Keycloak roles**. They deliver already proven application
metadata and existing canonical credentials through separately authorized Kubernetes
targets. Protocol/runtime tests use only target-realm `manage-clients`; realm
reconciliation and declared realm roles retain their existing additional grants.
See [runtime target RBAC and consent](architecture/application-identity.md#runtime-bindings).

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
| Organization principals in resource-server permissions | `manage-clients` + explicitly provisioned `view-users` | Client authorization and user/group reads throughout the target realm | Yes; not part of the common profile |
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

## Organization principals (0.5.0)

**Fresh ownership reads require target-realm `view-users`. This also permits
reading users throughout that realm.** It is an optional privacy tradeoff, not a
group-only permission and not an addition to the common profile. Use a separate
installation/identity where that read scope crosses a trust boundary. The operator
never grants itself roles. Fine-grained group-only delegation is unqualified.

For organization-only ResourceServer reconciliation against existing objects,
the tested identity authenticates in master and has exactly the target proxy
roles `manage-clients` + `view-users`, with Full Scope Allowed off and matching
client role scopes. No `manage-users`, `manage-realm`, `manage-events`,
`realm-admin`, impersonation, realm creation or master management is required.
Referenced realm-role principals additionally need the existing `view-realm`
read authority (or the common profile's `manage-realm`). The mixed-role test uses
`manage-clients` + `view-users` + `view-realm`. Creating/reconciling the
HankoOrganizations themselves retains the separate group-writer profile;
ResourceServer reconciliation does not create groups or change memberships.

These are per-capability minimums. All controllers register in the chart: a
process reconciling realms, organizations and grants needs the union of their
profiles (`manage-realm`, `manage-events`, `manage-clients`, `manage-users` for the
installed fixture). `manage-users` already supplies group reads. The narrower
two-role tests qualify the grant reconciler, not a chart profile that disables
the organization writer. Use one writer for each Kubernetes/provider object.

| Route used by organization grants | Required tested target role | Purpose |
| --- | --- | --- |
| `GET /admin/realms/{realm}/groups/{id}` | `view-users` | Fresh exact owner attributes, UUID, name and path |
| `GET /admin/realms/{realm}/group-by-path/{path}` | `view-users` | Verify the declared hierarchy resolves to that same owned UUID |
| `GET /admin/realms/{realm}/clients/{client}/authz/resource-server/policy` | `manage-clients` for Manage; existing `view-authorization` read profile for Observe | Complete bounded generic policy inventory |
| `GET .../authz/resource-server/policy/group` | Same authorization read authority | Complete typed group-policy inventory |
| `POST .../authz/resource-server/policy/group` and `PUT .../policy/group/{id}` | `manage-clients` | Create/update the owned group policy |
| `DELETE .../authz/resource-server/policy/{id}` | `manage-clients` | Delete only journal-owned policy IDs |

Existing client, resource, scope, permission and journal routes are unchanged and
listed in the operation inventory below. `query-groups` can list groups but
cannot supply the exact individual ownership reads: it is not a substitute for
`view-users`. Real HTTPS tests on 26.7.5 and 26.8.0 prove this profile succeeds
and that user creation/modification, group creation/hierarchy/membership writes,
impersonation, realm creation and master-client administration are denied.

Declare principals by HankoOrganization name in the ResourceServer namespace:

```yaml
principals:
  - kind: organization
    ref: europe
    includeDescendants: true
```

Omit `includeDescendants` (or set false) for Europe only. True includes Europe
and its current declared HankoOrganization descendants in the same namespace
and realm. It excludes foreign/markerless provider children and prefix siblings
such as Europe-sibling. Desired state accepts object references, not group paths,
UUIDs or native Keycloak Organization IDs. The optional platform Projection
condition and PositionID do not authorize access. Existing role mappings and
role/application/service-account grants retain their semantics; overlapping
allow paths are valid alternatives.

Resolution reads a complete namespace inventory (maximum 1,024 organizations),
requires current processed generation and Synced=True on every selected node and
ancestor, then freshly verifies exact singleton name/namespace/Kubernetes UID
markers and provider name/path/UUID. Status is a locator, never ownership proof.
New grants reject the legacy markerless-group fallback. Cycles, hierarchy
mismatch, more than 32 hierarchy edges, more than 128 distinct group definitions
per permission, or more than 256 owned policies fail before authorization writes.

Each permission has one owned group policy containing the sorted union of
verified UUIDs, with **every `extendChildren=false` and no groupsClaim override**.
Native Keycloak subtree inheritance is not used. Generic and typed observations
must agree to prove synchronization. Keycloak may retain a deleted group's UUID
only in generic config; this reports incomplete evidence. Manage may replace the
bindings of a journal-owned policy with the freshly verified desired set, but
only consistent read-back can certify InSync. Foreign policies are not repaired
or adopted. Removing a grant or ResourceServer deletes only its owned authorization
objects, preserving groups, organizations and still-required role/client policies.

The plan privately binds the inventory, UID/generation/realm/parent/sync state,
verified ancestry and provider group identity/path. Uncached Kubernetes and fresh
provider reads rebuild those dependencies immediately before and after execution.
An indexed namespace-local organization watch also catches previously unknown
descendants and status changes. More than 1,024 affected ResourceServers refuses
watch fan-out and retains periodic reconciliation rather than truncating it.
Unrelated namespace inventory changes can conservatively stale a plan.

This is an **applied UUID snapshot**. Moving/removing a descendant requires a
successful policy reconciliation to remove its UUID. The previous provider grant
can remain during failure or lost connectivity; no instantaneous revocation or
existing-token invalidation is promised. For urgent incidents, revoke provider
permissions/tokens directly and investigate before resuming the operator.

Missing group-read authority produces `OrganizationReadUnavailable`, no
authorization mutation and historical applied proof only. Check the bounded
finding, `Ready`, observation completeness, evaluated/applied plan hashes and
applied generation before claiming current state. `OrganizationPrincipals` and
`OrganizationDescendants` capabilities indicate qualified adapter semantics,
not effective credential authority. Provider payloads, subjects, memberships,
secrets and tokens are not exported to status. Bounded structural
explanation/provenance is described below and never evaluates individual subjects.

## Optional structural role provenance reads

Explanation adds only read operations. It never grants permissions to itself or
broadens the policy writer. A realm-role principal always retains its generic
structural path, even when no HankoOrganization maps it.

| Read | Existing target-realm role | Purpose / scope |
| --- | --- | --- |
| `GET /admin/realms/{realm}/groups/{group}/role-mappings` | `view-users` | Direct realm/client mappings of each strictly owned group; also permits target-realm user reads. |
| `GET /admin/realms/{realm}/roles/{role}` and `/composites` | `view-realm` | Fresh realm-role identity and each direct composite edge throughout the target realm. |
| `GET /admin/realms/{realm}/clients/{client}/roles/{role}` and `/composites` | `view-clients` (already included by the qualified `manage-clients` writer) | Client-role roots and edges; client UUIDs remain private. |

The qualified mixed Manage account uses **manage-clients + view-users +
view-realm**, on the target realm only. Observe uses **view-clients +
view-authorization + view-users + view-realm** for the same deeper evidence.
No manage-users, realm-admin or global authority is added to these profiles.
The existing organization writer remains a separate provisioning capability.

For a role-only ResourceServer, removing optional view-users while retaining
manage-clients + view-realm preserves synchronized authorization. The structural
explanation becomes incomplete with `AuthorizationExplained=False` and a bounded
`ProvenanceReadUnavailable` finding. It induces no policy writes. An explicit
organization principal still needs its mandatory ownership read before execution.
Transient composite/role-read failures have the same independent evidence behavior.
All reads remain HTTPS-authenticated, response-bounded and redirect-rejecting.

## Application protocols in 0.5.0

OIDC and the bounded SAML application/client-role contract use target-realm
`manage-clients` only; real protocol/lifecycle tests omit realm, event, user,
broker and global administrator grants. The newly inventoried client-role PUT
repairs descriptions under that same role and is denied to a no-role identity.
Declared realm-role scope writes additionally need `manage-realm`; the v0.2
manifest migration fixture verifies this profile. `view-realm` alone does not
permit those scope writes on the qualified versions. Optional inbound broker
mappers still need `manage-identity-providers`.

Public OIDC discovery and SAML metadata GETs need no Admin API role. They use the
configured verified CA transport, bounded gateway and no administrative bearer
header. SAML does not need private realm signing-key retrieval, per-application
client-secret access, user provisioning or impersonation authority. Bootstrap
setup of the disposable login user remains outside operator semantics. See the
[application contract and approved legacy migration](architecture/application-identity.md).

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
| client-roles | GET,PUT,DELETE | `/admin/realms/{realm}/clients/{client}/roles/{role}` | view-clients / manage-clients |
| client-roles | GET | `/admin/realms/{realm}/clients/{client}/roles/{role}/composites` | view-clients |
| client-scopes | GET,POST,DELETE | `/admin/realms/{realm}/clients/{client}/scope-mappings/realm` | view-clients / manage-clients and permission to map the realm role |
| protocol-mappers | GET,POST | `/admin/realms/{realm}/clients/{client}/protocol-mappers/models` | view-clients / manage-clients |
| protocol-mappers | PUT,DELETE | `/admin/realms/{realm}/clients/{client}/protocol-mappers/models/{mapper}` | manage-clients |
| identity-providers | GET,POST | `/admin/realms/{realm}/identity-provider/instances` | view-identity-providers / manage-identity-providers |
| identity-providers | PUT,DELETE | `/admin/realms/{realm}/identity-provider/instances/{alias}` | manage-identity-providers |
| identity-provider-mappers | GET,POST | `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers` | view-identity-providers / manage-identity-providers |
| identity-provider-mappers | PUT,DELETE | `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{mapper}` | manage-identity-providers |
| groups | GET | `/admin/realms/{realm}/group-by-path/{path...}` | view-users or manage-users |
| groups | GET,POST | `/admin/realms/{realm}/groups` | view-users / manage-users |
| groups | GET,PUT,DELETE | `/admin/realms/{realm}/groups/{group}` | view-users / manage-users |
| group-cleanup-members | GET | `/admin/realms/{realm}/groups/{group}/members` | view-users or manage-users; cleanup existence only, max=1 |
| groups | GET,POST | `/admin/realms/{realm}/groups/{group}/children` | view-users / manage-users |
| group-roles | GET | `/admin/realms/{realm}/groups/{group}/role-mappings` | view-users |
| group-roles | GET,POST | `/admin/realms/{realm}/groups/{group}/role-mappings/realm` | view-users / manage-users and permission to map the realm role |
| group-roles | GET,POST | `/admin/realms/{realm}/groups/{group}/role-mappings/clients/{client}` | view-users / manage-users and permission to map the client role |
| organizations | GET,POST | `/admin/realms/{realm}/organizations` | view-organizations / manage-organizations or manage-realm |
| organizations | GET,PUT,DELETE | `/admin/realms/{realm}/organizations/{organization}` | view-organizations / manage-organizations or manage-realm |
| organization-cleanup-members | GET | `/admin/realms/{realm}/organizations/{organization}/members` | view-organizations or manage-organizations; cleanup existence only, max=1 |
| organization-idps | GET,POST | `/admin/realms/{realm}/organizations/{organization}/identity-providers` | view-organizations / manage-organizations (or manage-realm) and manage-identity-providers |
| organization-idps | DELETE | `/admin/realms/{realm}/organizations/{organization}/identity-providers/{alias}` | manage-organizations (or manage-realm) and manage-identity-providers |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/scope` | view-authorization / manage-authorization or manage-clients |
| authorization | GET,PUT,DELETE | `/admin/realms/{realm}/clients/{client}/authz/resource-server/scope/{object}` | view-authorization / manage-authorization or manage-clients |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/resource` | view-authorization / manage-authorization or manage-clients |
| authorization | GET,PUT,DELETE | `/admin/realms/{realm}/clients/{client}/authz/resource-server/resource/{object}` | view-authorization / manage-authorization or manage-clients |
| authorization | GET | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/{object}/associatedPolicies` | view-authorization or manage-authorization or manage-clients |
| authorization | GET | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy` | view-authorization or manage-authorization or manage-clients |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/role` | view-authorization / manage-authorization or manage-clients |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/client` | view-authorization / manage-authorization or manage-clients |
| organization-authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/group` | view-authorization / manage-authorization or manage-clients; strict group resolution additionally requires view-users |
| organization-authorization | GET,PUT | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/group/{object}` | view-authorization / manage-authorization or manage-clients |
| authorization | GET,PUT | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/role/{object}` | view-authorization / manage-authorization or manage-clients |
| authorization | GET,PUT | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/client/{object}` | view-authorization / manage-authorization or manage-clients |
| authorization | DELETE | `/admin/realms/{realm}/clients/{client}/authz/resource-server/policy/{object}` | manage-authorization or manage-clients |
| authorization | GET | `/admin/realms/{realm}/clients/{client}/authz/resource-server/permission` | view-authorization or manage-authorization or manage-clients |
| authorization | GET,POST | `/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/scope` | view-authorization / manage-authorization or manage-clients |
| authorization | GET,PUT | `/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/scope/{object}` | view-authorization / manage-authorization or manage-clients |
| authorization-native-dependencies | GET | `/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/resource` | view-authorization or manage-authorization or manage-clients |
| authorization | DELETE | `/admin/realms/{realm}/clients/{client}/authz/resource-server/permission/{object}` | manage-authorization or manage-clients |
<!-- admin-operation-contract:end -->


The 0.2 adapter qualification reads scope permissions with `fields=*` on the
existing collection route, and reads their associated policy IDs through the
explicitly inventoried `GET .../policy/{object}/associatedPolicies`. These are
bounded read operations under the existing target permissions. Real tests prove
common-profile success, read-only success and unprivileged HTTP 403; no new
administrative role is granted. They are needed for semantic idempotence because
Keycloak's default permission lists omit these relationships.

## Dedicated inventory identity

HankoImport always resolves sourceRef. Configure a separate external-mode
HankoKeycloakInstance against the same reviewed HTTPS endpoint/CA, with AdminRef
pointing to a dedicated client-credentials identity. It must have no realm-admin,
manage-*, master create-realm, impersonation or global administrator role.
A shared operator writer pool is never the inventory fallback. Credentials stay
in the referenced Secret; do not embed them in manifests.

| Inventory family | Target-realm read role | Scope and qualification |
| --- | --- | --- |
| Selected realms, realm roles/direct/effective composites | view-realm | Each selected realm; GET realm confirms UUID/full representation |
| OIDC/SAML/M2M clients, client roles, protocol mappers and scope mappings | view-clients | Each selected realm; no client-secret endpoint is called |
| Brokers and IdP mappers | view-identity-providers | Typed safe configuration projection; opaque secrets excluded |
| Structural groups/hierarchy and role mappings | view-users | No user/member endpoints; the role itself also grants user visibility |
| Native Organizations | view-organizations | Only when enabled; no member reads or feature-enabling write |
| Authorization Services graph | view-authorization | Paginated/typed scope/resource/policy/permission and association reads |

The full inventory CI identity uses these six read roles on the disposable target
realm. Bootstrap administration provisions fixtures and records mutation evidence;
normal inventory is authenticated as the constrained service account. Capability
profiles can omit unrelated roles, but failed required family reads must produce
incomplete coverage, not a misleading complete inventory. Every normal inventory
operation is a qualified GET except token acquisition. Mutations and credential
endpoints are deliberately rejected by the HTTPS inventory guard; Admin events
independently prove zero provider writes.

Read-only means mutation authority is absent, not credential confidentiality:
**Keycloak 26.7.5 view-clients can read the client-secret endpoint**, while the
qualified 26.8.0 behavior requires manage-clients there. The operator never calls
that endpoint in inventory and cannot make 26.7.5's role narrower. view-users also
has broader visibility than the structural subset the operator actually reads.
These are explicit native permission limitations, not extra operator behavior.

Kubernetes requires named GET of source AdminRef and TLSCARef Secrets; Secret
list/watch remain denied in the effective chart RBAC and are qualified on the
Kubernetes matrix. Imports generate Observe declarations and review evidence,
not approvals or provider ownership. See the
[implemented discovery contract](architecture/existing-keycloak-adoption.md#implemented-discovery-and-diff-47).

## Explicit reviewed leaf ownership acquisition

The [common acquisition executor](architecture/existing-keycloak-adoption.md#implemented-reviewed-leaf-acquisition-48)
adds no Admin API operation family or global privilege. Its sourceRef observer
uses a dedicated identity; ownership is written by the normal domain writer only
after normalized endpoint and realm UUID match the reviewed source.

| Capability | Target-realm reader | Separate target-realm writer | Deliberately omitted |
| --- | --- | --- | --- |
| Application/ServiceAccount leaf | view-realm, view-clients | view-realm, manage-clients | realm-admin, master administration, users/groups, brokers, credential routes |
| Realm-role leaf | view-realm | manage-realm | clients, users/groups, brokers, global realm creation |

This is the leaf profile, not the full-family HankoImport profile above. CI tests
actual production acquisition with separate reader/client-writer/role-writer clients
on HTTPS 26.7.5/26.8.0. Bootstrap administration only provisions fixtures and roles.
Every ownership PUT is client or role metadata; no credential retrieval/rotation
or child mutation is part of acquisition. Reader PUT and unrelated writer realm
creation/user mutation are denied. The native 26.7.5 view-clients credential-read
limitation remains visible; the operator's inventory guard denies that route on
both versions. manage-clients itself also grants credential authority, which the
acquisition path does not exercise. manage-realm is Keycloak's broader target-realm
role-management authority; it is not global administrator authority.

Restrict permission to change approval annotations and source credential/CA
references with Kubernetes RBAC. A candidate, imported label or successful status
alone does not approve provider mutation. Acquisition remains Observe and gains
no destructive finalizer or Secret. Explicit Manage requires an absent imported
latch, current provider ownership and the qualified preservation schema.

## Aggregate acquisition and adopted Manage

Use a separate source observer and domain writer, with authority limited to the
target realm. The [aggregate/preservation contract](architecture/existing-keycloak-adoption.md#implemented-aggregate-acquisition-and-native-preservation-49)
does not grant realm lifecycle ownership. Credential access begins only after
explicit qualified client/ServiceAccount Manage, not during acquisition.

| Capability | Target-realm observer | Separate target-realm writer | Excluded authority / limitation |
| --- | --- | --- | --- |
| Application/ServiceAccount with existing Authorization Services | view-realm, view-clients; view-authorization for independent graph review | view-realm, manage-clients | No manage-realm, user/group/broker mutation or global realm administration. The client receipt does not acquire the graph. |
| Selective ResourceServer | view-realm, view-clients, view-authorization | view-realm, manage-clients, manage-authorization | No manage-realm, realm deletion/security mutation, users or global realm creation. V2 selects safe nodes only. |
| Organization group + already-enabled native root | view-realm, view-users, view-organizations, view-identity-providers, view-clients | view-realm, manage-users, manage-organizations, view-identity-providers, view-clients | No manage-realm, client management, IdP mutation or global realm administration. manage-users also grants target-realm user authority even though the operator does not provision members. |
| Adopted realm-role definitions/composites | view-realm, view-clients for client-composite visibility | manage-realm | Broader target-realm security/lifecycle authority is inseparable from this legacy role-definition permission. This profile cannot honestly claim target-realm DELETE/security PUT denial. It has no global realm creation or other-realm authority. |

`view-clients` on the Organization profile is necessary to observe foreign client
role mappings consistently through both reader and writer on 26.8.0; without it,
caller-dependent provider representations fail the acquisition comparison.
It does not authorize the operator to modify those clients. The native 26.7.5
credential-visibility limitation of view-clients remains: the inventory transport
guard still refuses client-secret/service-account-user routes on both versions.

The aggregate writers prove realm DELETE, realm security PUT and global realm
creation return 403 on real HTTPS Keycloak. Bootstrap administration provisions
disposable foreign fixtures and scoped identities only. Ownership acquisition
does not use user/member reads; destructive Organization safety uses only bounded
`first=0&max=1` membership existence, without retaining identities.

### Dedicated HankoRole writer: target-realm exception

**Adopted HankoRole Manage remains enabled.** On Keycloak 26.7.5 and 26.8.0,
`manage-realm` is the currently qualified built-in authority for creating,
updating, deleting and composing realm-role definitions. Keycloak does not
currently provide a qualified built-in role-definition-only permission.
Fine-grained role mapping, composite mapping and client-scope mapping permissions
are not a qualified substitute for definition create/update/delete.

Grant only `<target-realm>-realm/manage-realm` to this writer. Disable Full Scope
Allowed and permit exactly that client-role scope. Use a dedicated role-writer
identity per target realm, with separate watched declarations, wherever the
deployment architecture permits it. Do not grant `realm-admin`, master
`manage-realm`, master/global `admin`, `create-realm` or authority on unrelated
realms. Authentication in master does not require any of those grants.

This credential can also change target-realm security/configuration and delete
that target realm. **Credential compromise therefore has a target-realm blast
radius broader than role definitions.** Ownership markers, reviewed candidates,
UIDs and receipts constrain the controller's authorized behavior; they do not
restrict the technical capabilities of the Keycloak token.

The narrow §117 exception applies only to HankoRole's credential authority.
Normal HankoRole writes stay on the inventoried realm-role definition/composite
endpoints: `POST /admin/realms/{realm}/roles`,
`PUT,DELETE /admin/realms/{realm}/roles/{role}` and
`POST /admin/realms/{realm}/roles/{role}/composites`. Bounded identity and
role/composite reads support current ownership and authority checks. HankoRole
never sends realm configuration/security PUT or realm DELETE. A role receipt
confers no realm lifecycle ownership. An imported/external HankoRealm remains
Observe-only: no realm ownership acquisition, lifecycle finalizer, security
reconciliation or deletion from its HankoRole children.

Real HTTPS tests preserve both sides of this distinction. A client-only writer
cannot update/delete realm-role definitions. The dedicated role-only writer can
change security and delete its **disposable target realm** through direct probes,
but cannot change/delete master or an unrelated realm or create another realm.
The normal reconciliation transport separately fails the test if a child calls
realm security PUT/realm DELETE, or if HankoRole mutates an endpoint outside the
role inventory. The writer has Full Scope Allowed disabled and its exact permitted
role scope is asserted. Direct blast-radius probes are not controller behavior.
Application, ServiceAccount, ResourceServer and Organization writers continue
to prove realm security mutation and realm deletion are denied.

Adopted-role deletion remains conservative: without qualified absence of every
foreign role reference, retain `CleanupConflict` and the finalizer rather than
deleting the provider role. An explicit return to Observe withdraws lifecycle
participation and preserves the role. The exact reviewed candidate, target UID,
provider UUID, receipt, qualified native preservation and explicit Observe →
Manage transition remain required; neither status nor a matching name is authority.
