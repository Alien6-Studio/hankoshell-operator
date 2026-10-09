# Organizational authorization: accepted 0.4 direction

This document resolves [RFC #40](https://github.com/Alien6-Studio/hankoshell-operator/issues/40)
when its architecture PR is merged. It defines the implementation direction,
not an available 0.4 API. Packaging remains **0.3.0**; the signed v0.3.0 source
boundary is immutable. Implementation is tracked in
[#41](https://github.com/Alien6-Studio/hankoshell-operator/issues/41) and bounded
explanation in [#42](https://github.com/Alien6-Studio/hankoshell-operator/issues/42).

## Decision

Extend the existing **HankoResourceServer authorization aggregate** with an
organization principal, explicit direct-only/descendant semantics and a Keycloak
group-policy adapter. Preserve role composition. Do not add HankoEntitlement,
HankoUser or another CRD. This PR changes no public API enum, controller or
production adapter; there are still 16 experimental v1alpha1 CRDs.

Descendants mean **declared, current, owned HankoOrganization descendants**.
Compile their bounded UUID set as direct-only group definitions. Do not translate
the portable descendant choice to native extendChildren=true: the experiment
shows that it also allows a foreign, markerless subgroup.

The decision depends on the qualified group-policy semantics and explicit
optional read authority described below. It does **not** authorize silently
widening the standard Keycloak permission profile. A missing group read or
ownership proof must block an organizational grant before mutation.

## Domain and current composition

The model is `subject × organization × resource × action`:

- **Subject:** an authenticated runtime subject whose membership is provider/IdP
  data. Hanko declares policy structure, not individual humans or memberships.
  Qualification uses disposable human fixtures; it does not certify every
  service-account or federated membership flow.
- **Organization:** a same-namespace HankoOrganization reference, resolved to its
  owned structural group. Native Keycloak Organization membership is distinct.
- **Resource/action:** the existing ResourceServer resource and scope. No second
  resource namespace, action vocabulary or policy effect is introduced.

| Existing object | Current authority |
| --- | --- |
| HankoOrganization | Hierarchical Keycloak groups, root native Organizations, realm/client-role mappings; optional platform projection has separate readiness. |
| HankoRole | Realm roles and their configured composites. |
| HankoResourceServer | Scopes, resources and allow-only permissions; principal kinds are realm_role, application and service_account. |
| HankoApplication | Application identity and the resource-server client relationship. |
| IAM Contract Engine | Normalized intent, capabilities, locally compiled plans, ownership, freshness, observation and findings. |

There is no organization principal in the current CRD. An organization can map
a realm role whose corresponding HankoRole is referenced by a ResourceServer
permission. Organization role mappings currently use provider role names;
the ResourceServer principal uses the HankoRole object name and resolves its
`spec.name`. Client-role mappings also exist, but a portable `client_role`
principal does not. Native client-role policies must not be advertised as a new
portable principal by this RFC.

Role composition is useful and remains supported. Reusing a role across groups
can broaden several organizations at once, however, and provider group-role
inheritance applies to descendants without a per-permission direct-only choice.
The role name alone loses the organizational source of a grant.

## Options compared

| Criterion | A: role composition only | B: organization principal (chosen) | C: dedicated entitlement CRD |
| --- | --- | --- | --- |
| Privileges | Existing client/role authorization profile; organization writer separately maps roles. | Same policy writer plus explicit group ownership reads; built-in profile needs view-users. | Same provider privileges as its implementation; a CRD does not reduce them. |
| Provider objects | Role mappings plus role policies/permissions; shared roles can reduce objects. | At most one additional group policy per permission, holding sorted group definitions; existing permissions remain the authority. | Same policies plus another Kubernetes object/controller. |
| Update cost | A shared-role edit can affect unrelated grants. | Recompile affected grants and dependencies; UUID-based policy updates are in-place. | Additional coordination across aggregates and controllers. |
| Inheritance | Group-role and composite-role inheritance; no per-grant direct-only group rule. | Direct-only default; declared owned descendants explicitly expanded as direct-only UUID alternatives. | Still needs the same inheritance decision. |
| Explanation | Must reconstruct role mappings/composites; generic roles can have unrelated sources. | Organization source and descendant choice are explicit; role provenance remains visible. | An entitlement name is useful only if it owns independent authority. |
| Portability | Existing portable role intent with provider-qualified mapping. | Portable organization reference/semantics, capability-dependent implementation. | A new API is not evidence of provider parity. |
| Migration/failure | No migration, but indirection and shared-role broadening remain. | Additive opt-in; stale group/ownership/permission failures fail closed. | New finalizers, ownership/conflicts, conversion and graduation burden. |

A is retained as a valid composition path, but rejected as the **sole** 0.4
model. C currently duplicates permission lifecycle/ownership inside
HankoResourceServer. Independent delegated or cross-aggregate entitlement
authority would need a separate RFC; a noun alone does not justify a 17th CRD.

## Reproducible provider characterization

The committed
[real-server experiment](../../internal/controller/keycloak_organizational_authorization_test.go)
uses the existing digest-pinned HTTPS fixtures for **26.7.5 and 26.8.0**. It is
included in the full real Keycloak suite, including race checking:

```sh
make keycloak-integration-test KEYCLOAK_VERSION=26.7.5
make keycloak-integration-test KEYCLOAK_VERSION=26.8.0
```

To run just this characterization, set the version and use
`go test -tags=keycloak_integration -race -count=1 -run '^TestRealKeycloakOrganizationalAuthorizationCharacterization$' -v ./internal/controller`.
Docker is required. Bootstrap creates fixtures and membership only. Dedicated
client-credentials accounts exercise the Admin API. Actual subject bearer tokens
exercise UMA `response_mode=decision`, proving successful allow responses and
HTTP 403 denials, rather than relying on an administrative simulation alone.
Tokens/passwords remain in memory and are redacted; no real user is provisioned.

Both versions produced the following results; no material difference was found:

| Characterization | 26.7.5 | 26.8.0 |
| --- | --- | --- |
| Typed policy `policy/group` | groups[{id: UUID, extendChildren: boolean}], groupsClaim unset | Same |
| Generic `policy/{id}` | Group definitions serialized in config.groups | Same |
| Path input | Accepted and resolved to group UUID on typed read-back | Same |
| Direct-only Europe | Europe member allowed; France, Paris, Germany, outside/native-only members denied | Same |
| Native Europe with descendants | Europe/France/Paris/Germany and markerless Europe/External allowed; Africa and Europe-sibling denied | Same |
| Explicit owned descendant UUID set, every extendChildren=false | Europe/France/Paris/Germany allowed; markerless Europe/External, Africa and Europe-sibling denied | Same |
| Direct France | France allowed; Paris, Europe, Germany denied | Same |
| France descendants + Africa | OR across groups; France/Paris/Africa allowed, other branches denied | Same |
| Group + role allow overlap | Both sources allowed; inherited role can allow France while direct Europe group policy does not | Same |
| Resource/action update | Existing permission moved to credit-note/write; old invoice/read denied; restoration converged | Same |
| Repeated policy update | Same UUID and typed representation after identical PUT | Same |
| Rename | UUID policy survived France rename; group read-back returned the new path | Same |
| Native reparent evaluation | Paris moved to Africa; native France descendant grant stopped allowing it, including with the previously obtained subject access token | Same |
| Explicit UUID snapshot after move | Referencing the moved Paris UUID still allowed it; removing that UUID revoked the fresh UMA decision | Same |
| Native Organization member | Real native membership alone did not satisfy the Europe structural-group policy | Same |
| Same-name policy create | HTTP 409; existing identity retained | Same |
| Grant deletion | Permission/group policy removed; organization/group, resource, foreign policy and role-based access survived | Same |
| Missing client authority | Policy/resource/scope/permission mutation and Admin evaluation denied | Same |

The sibling-prefix regression is deliberate: Keycloak's
[CVE-2026-18203 report](https://github.com/keycloak/keycloak/issues/51280)
describes an earlier delimiter error. The qualified images deny Europe-sibling
under a Europe descendant grant. This result does not extend qualification to
other versions or token-claim policy configurations.

The experiment characterizes provider primitives. The future adapter's journal,
stale-plan and forged-status enforcement are implementation acceptance criteria,
not implemented features demonstrated by these raw REST helpers.
Renames/reparenting are bootstrap provider operations, not newly qualified
HankoOrganization update lifecycle guarantees. The future grant resolver must
reject a provider hierarchy inconsistent with current Hanko desired state.

## Exact permission contract and tradeoff

The fixture accounts authenticate in master with **only target-realm delegated
management-client roles** (`managed-realm`). They receive no master-realm
management grants. The roles/routes tested are:

| Operation | Required tested role | Scope and limit |
| --- | --- | --- |
| Client/resource-server reads, scopes/resources, policy/group CRUD, scope-permission CRUD | manage-clients | All clients/resource servers in the target realm, not a single client. |
| GET groups/{id}, group-by-path/{path}, complete non-brief groups list with owner attributes | view-users | Users/groups throughout the target realm; not group-only read authority. |
| POST authz/resource-server/policy/evaluate for a known fixture subject | manage-clients | Administrative client authorization evaluation; not a proposed public per-user API. |
| Real UMA request | Subject's own bearer token | Runtime provider membership and the requested audience/resource/scope; no admin role. |
| Fixture creation, membership, role mapping, rename/reparent and native Organization setup | Bootstrap only | Provisioning is not new ResourceServer authority. |

`manage-clients` alone successfully performed all policy operations. Without
view-users, direct group/path reads returned 403. Adding query-groups made the
list route return 200 but did not expose the owned group for proof; individual
group reads still returned 403. It is **insufficient** for the selected resolver.
view-users supplied the required attributes/path and also allowed GET users.

This additional user-read authority is a real cost of B compared with role-only
authorization. It is acceptable only as an explicitly configured optional
profile on the selected target realm. The existing standard profile remains
unchanged; no controller may grant itself roles. If an installation cannot
accept this read scope, it keeps role composition or leaves organization grants
disabled. Fine-grained group-only delegation has not been qualified here and
must not be presented as a supported substitute.

The tests exclude group/user mutation, impersonation, realm creation and master
client administration for both constrained profiles. No manage-users,
realm-admin, global administrator, new credential Secret or user provisioning
is required by the group-policy path. The existing organization writer retains
its separately documented broader provisioning permissions. See the
[current permission guide](../keycloak-permissions.md); these future group-policy
routes do not silently become current production client operations.

## Principal and inheritance semantics

The conceptual future principal identifies a HankoOrganization by Kubernetes
object name in the ResourceServer namespace. Provider UUIDs, paths and native
Organization IDs are never accepted as portable desired state. The exact public
field spelling is reviewed in #41; the semantic choice is fixed here:

- direct-only is the default, normalized identically for absent/false;
- descendants require an explicit request and qualified capability;
- descendants are the same-namespace, same-realm declared HankoOrganization tree,
  with every node independently current and provider-owned; foreign provider
  subgroups are not added to the UUID set;
- the existing map-list identity `kind + ref` remains one entry per organization;
  direct/inherited duplicates cannot coexist under that key;
- provider group IDs are adapter inputs, with extendChildren=false on every
  definition, including explicitly expanded descendants;
- groupsClaim overrides and arbitrary token-claim membership are not part of
  this portable capability; membership is evaluated by the provider;
- multiple valid allow paths are alternatives, with existing AFFIRMATIVE
  permission semantics, not conflicting deny/allow rules.

Four separate structures must remain distinguishable: the HankoOrganization
tree, role composites, inherited Keycloak group roles and group-policy
descendants. A parent group's role can allow a child via composition even when
the parent's direct-only group grant does not. Explanation must show that role
source. A native root Organization can support brokering/domain membership, but
it is not automatically the structural-group authorization primitive.

The fixtures establish provider membership directly. An external IdP's complete
group-population/broker flow is not newly qualified. Existing access/RPT tokens
are not automatically revoked by a grant change; applications must use their
authorization/enforcement and token-lifetime policy. A reused access token's
fresh UMA decision reflected the tested hierarchy change; this is not a general
offline-token or session-revocation guarantee.

This is an intentional difference from native Keycloak subtree inheritance.
Existing role composition can still allow members of undeclared subgroups through
inherited roles; that is an independent valid path, not an organization grant or
a reason to introduce deny. A future declared descendant becomes eligible only
after fresh ownership/synchronization proof and plan recompilation. A complete
bounded namespace inventory and its dependency fingerprint detect additions as
well as changes/deletions; unchanged parent generation alone is insufficient.

The explicit UUID set is an applied snapshot. A moved node retains its UUID;
Keycloak therefore continues to honor an old enumerated entry until the policy
is updated. Reconcile after dependency changes and never execute a stale new
plan. This does not promise instantaneous runtime revocation: previous provider
grants can remain during reconciliation failure or lost connectivity. Status
must expose stale/incomplete proof, and incident response may require direct
provider revocation. Native subtree behavior is not a safe shortcut around that
consistency boundary.

## Ownership and freshness before provider writes

Resolve organization references using current Kubernetes reads. Require exact
same namespace and realmRef as the ResourceServer, and matching resolved provider
realm/authority. Require a current Synced condition and processed generation;
optional platform Projection readiness/overall phase is not provider authority.
Fresh provider reads must independently verify the exact nonempty singleton
organization name/namespace/UID markers and the current structural hierarchy.

`status.groupID` and groupPath are locators/evidence only. A matching name, forged
status or mutable path does not establish ownership. The existing organization
reconciler has a markerless legacy-ID compatibility path; **new organization
grants must not inherit that status-only fallback**. A legacy group needs reviewed
administrator-established ownership markers before it can receive this capability.
No full organization IAM-plan migration is required to make these reads, and no
automatic adoption is introduced by this design. Keycloak administrators remain
trusted for provider owner markers, as in the existing authorization journal.

Compile and revalidate a bounded dependency snapshot containing:

- ResourceServer UID/generation, realm and existing authority preconditions;
- organization UID/generation, realmRef, desired name/parentRef and current sync;
- relevant ancestor refs/UIDs/generations and validated provider hierarchy;
- complete bounded declared descendant closure when requested, with graph
  fingerprint and every included node's UID/generation/provider proof;
- resolved group UUID, path and ownership fingerprint, privately in the provider
  plan identity, never portable intent;
- complete relevant policy observation and exact ResourceServer owner journal.

Recreation, changed generation/realm/parent, rename/path drift, owner-marker
change or changed provider resolution must stale the compiled plan before writes.
Refresh after every external wait/retry. Reject cycles, excessive ancestry and
unsafe/ambiguous name/path representation rather than infer identity from a
prefix. Membership itself remains runtime data, not an exported intent hash.

Group policies reuse the existing ResourceServer client ownership journal
`hanko.sh/resource-server-ownership`: owner UID, created object IDs and bounded
logical references, checkpointed before dependent writes. A same-name unowned
policy is a conflict; the fixture's 409 is not adoption permission. Grant cleanup
deletes only journal-proven policies/permissions and preserves foreign/native
objects, role paths, organizations and the resource server.

## Observation, budgets and capabilities

Extend the existing generic policy inventory **and typed group-policy reads**;
the current typed adapter handles role/client only. Normalize UUID group
definitions into resolved organization semantics before domain observation hashes.
Sort alternatives, preserve descendant choices and distinguish unknown/foreign
types. Incomplete reads, inconsistent generic/typed representation or lost owner
proof cannot certify synchronization. Foreign token-claim/native policies stay
visible as findings, including when their access impact cannot be fully explained.

Retain current bounded collection and owner-journal discipline. One group policy
per permission can hold its organization alternatives. Mixed role/client/group
permissions can exceed the existing **256-policy journal bound** at maximum
permission cardinality; #41 must budget the total before writes and fail closed
rather than silently increase limits. The existing scope/resource/permission and
response bounds still apply.
The descendant closure must also fit a first design bound of 128 distinct group
definitions per permission and 32 hierarchy edges; refuse incomplete/over-budget
closure rather than truncate it into a proven grant. These are implementation
validation budgets, not a changed current public schema.

Explicit future capability evidence separates OrganizationPrincipals and
OrganizationDescendants. It means qualified Hanko semantics, not merely that a
server has groups, and it never auto-grants administrative privileges. Unsupported
inheritance, missing read permission and foreign/native representation generate
stable findings before execution. Organization ref + descendant intent is
portable; its realization is capability-dependent. No second provider parity is
claimed or required for 0.4.

## Bounded effective explanation

#42 introduces an internal normalized **policy-structure** explain DTO, with a
bounded ResourceServer status projection reviewed during implementation. A row
contains organization reference, ResourceServer/resource/scope, effect allow,
source permission/principal, direct/descendant relationship, ancestor source and
current evaluated/applied plan evidence. It is not a per-user decision endpoint.

Keep distinct provenance for direct organization, inherited ancestor,
organization-mapped realm role, mapped client role/native finding, generic role
unrelated to organization, application and service-account paths. Composite-role
closure/mapping must be actually observed before attributing a source. If that
relationship cannot be proved, report it as unknown/native rather than invent
organization membership. Explain all valid overlapping alternatives.

First design budget: **256 paths**, **32 ancestry edges per path**, bounded
condition/findings messages, and explicit incomplete/truncated state. Only
complete current observations can claim complete structural explanation. No user
names, membership lists, PII, bearer tokens, secret values/hashes, full policy
payloads or provider UUIDs enter the primary explanation. Policy coverage does
not imply `allowed=true` for an arbitrary subject or exclude other native grants.

Conflicts are unresolved refs, realm mismatch, stale generation/hierarchy,
missing/ambiguous ownership, foreign identity collisions, incompatible native
representation, unsupported inheritance and incomplete reads. Insufficient
group-read privilege is a blocking dependency/authority finding. Overlapping
valid allows are not conflicts. There is no explicit deny or new precedence model.

## Migration, security and remaining review

Existing role grants remain untouched. Enabling an organization principal is an
additive administrator decision; it does not remove roles, change memberships,
transfer ownership or create a native Organization. Removing it cannot own the
organization lifecycle. Recreated organizations require fresh UID proof.

Implementation tests must cover forged status, foreign/markerless groups,
ambiguous markers, stale paths, hierarchy races, hidden native policies, read
budgets, new descendant discovery, foreign-child exclusion, privilege omission
and owned-only cleanup, in addition to the provider
characterization. No new user/membership/LDAP API, credentials, deny model, Hub
transport, Continuum change or second provider belongs to this RFC.

The accepted semantic decision is complete. The exact public field/status shape
and names, group-only fine-grained delegation, external IdP population and broader
operational/provider qualification remain explicitly separate reviews. They do
not justify advertising those capabilities now. Next: #41 implements the accepted
grant model; #42 follows its proven observations and provenance.
