# Organizational authorization: accepted 0.4 direction

This is the implemented **0.4.0 Organizational Authorization** source contract,
accepted in [RFC #40](https://github.com/Alien6-Studio/hankoshell-operator/issues/40),
with grants in #41 and bounded explanation in #42. Packaging metadata is 0.4.0;
public delivery remains independent in #21. Historical source tags are immutable.

## Decision

Extend the existing **HankoResourceServer authorization aggregate** with an
organization principal, explicit direct-only/descendant semantics and a Keycloak
group-policy adapter. Preserve role composition. Do not add HankoEntitlement,
HankoUser or another CRD. The additive organization principal and bounded status projection retain the
16 experimental v1alpha1 CRDs.

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
| HankoResourceServer | Scopes, resources and allow-only permissions; principal kinds are realm_role, application, service_account and organization. |
| HankoApplication | Application identity and the resource-server client relationship. |
| IAM Contract Engine | Normalized intent, capabilities, locally compiled plans, ownership, freshness, observation and findings. |

An organization can also map
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

The experiment characterizes provider primitives. Separate production-reconciler
tests qualify journal ownership, stale plans, forged status and explanation;
those guarantees do not follow from raw REST helpers alone.
Renames/reparenting are bootstrap provider operations, not newly qualified
HankoOrganization update lifecycle guarantees. The implemented grant resolver must
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
[current permission guide](../keycloak-permissions.md); optional group-policy
and provenance routes do not silently broaden the common credential profile.

## Principal and inheritance semantics

The implemented principal identifies a HankoOrganization by Kubernetes
object name in the ResourceServer namespace. Provider UUIDs, paths and native
Organization IDs are never accepted as portable desired state. The public fields are kind, ref and includeDescendants; the semantic choice is:

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

The adapter observes generic policy inventory **and typed role/client/group reads**. Normalize UUID group
definitions into resolved organization semantics before domain observation hashes.
Sort alternatives, preserve descendant choices and distinguish unknown/foreign
types. Incomplete reads, inconsistent generic/typed representation or lost owner
proof cannot certify synchronization. Foreign token-claim/native policies stay
visible as findings, including when their access impact cannot be fully explained.

Retain current bounded collection and owner-journal discipline. One group policy
per permission can hold its organization alternatives. Mixed role/client/group
permissions can exceed the existing **256-policy journal bound** at maximum
permission cardinality; the compiler budgets the total before writes and fail closed
rather than silently increase limits. The existing scope/resource/permission and
response bounds still apply.
The descendant closure must also fit a first design bound of 128 distinct group
definitions per permission and 32 hierarchy edges; refuse incomplete/over-budget
closure rather than truncate it into a proven grant. These are explicit
implementation validation budgets.

Explicit capability evidence separates OrganizationPrincipals and
OrganizationDescendants. It means qualified Hanko semantics, not merely that a
server has groups, and it never auto-grants administrative privileges. Unsupported
inheritance, missing read permission and foreign/native representation generate
stable findings before execution. Organization ref + descendant intent is
portable; its realization is capability-dependent. No second provider parity is
claimed or required for 0.4.

## Bounded effective explanation

`HankoResourceServer.status.authorizationExplanation` is normalized structural
provider evidence. It does not evaluate an individual subject, enumerate
memberships or promise that every user of an organization has access.

```yaml
status:
  authorizationExplanation:
    sourceGeneration: 4
    sourcePlanHash: sha256:<64 hex characters>
    sourceObservationHash: sha256:<64 hex characters>
    source: Applied
    complete: true
    truncated: false
    explanationHash: sha256:<64 hex characters>
    paths:
      - permission: invoice-read
        resource: invoice
        action: read
        sourceKind: organization
        sourceRef: europe
        organizationRef: france
        relationship: descendant
        ancestry: [europe, france]
```

`Applied` means current Manage application/read-back matches the evaluated plan.
`Observed` means provider structure was observed without proving Hanko applied it,
including Observe mode. There is no Desired source. Source generation and plan
hash identify the evaluated input; they never make an older generation current.
The explanation sourceObservationHash domain-separates the authorization binding
observation plus the additional verified organization/role provenance snapshot.
It is distinct from the ordinary observedStateHash, which remains independent of
optional deeper reads. explanationHash uses the existing IAM contract version,
authorization/explanation domain and normalized public semantics, including source,
completeness, truncation and the actually emitted paths. Hashes grant no authority.

Paths use existing permission/resource/scope names and Hanko principal refs.
Resource × action pairs require observed permission-resource/scope bindings and
resource-scope intersection. A permission with no explicit resources expands only
to observed declared resources supporting its scopes. No wildcard is invented.
An owned policy and observed permission-policy binding must prove each path.
Unknown, foreign, negative/unsupported or inconsistent bindings cannot certify it.

| Source | Relationship / meaning |
| --- | --- |
| organization | direct for its own verified group; descendant with declared Hanko ancestry for explicitly expanded owned nodes |
| realm_role | generic without organization attribution; the role can be granted outside known organizations |
| realm_role | mapped_role for an observed direct group realm-role mapping; mapped_composite_role for a proven realm-role chain |
| realm_role | mapped_client_role for a directly mapped client-role chain reaching the relevant realm role |
| application / service_account | generic observed client-policy alternative; no invented organization membership |

A role chain carries kind, declared role ref/name and a declared clientID for
client roles. Direct mappings and each composite edge are read from Keycloak;
Kubernetes role specs supply labels only. The final role UUID must match the
private identity observed in the actual role policy; same-name recreation cannot
bridge an old policy to a new mapping. Cross-client intermediate chains that
cannot be safely labelled remain ambiguous/incomplete. Unknown or ambiguous labels produce a
gap instead of raw provider names/IDs. Declared descendant group-role inheritance
retains its mapping origin in ancestry. Generic role paths always remain, even
when no organization maps the role. Native client-role effects do not introduce
a client_role ResourceServer principal. Different valid overlapping origins
remain separate; exact normalized duplicates collapse.

Paths are sorted by permission, resource, action, source kind/ref, organization,
relationship, ancestry and role chain. Public limits are **256 paths**, **33
ancestry refs / 32 edges** and **33 role steps / 32 edges**, with bounded strings,
enums and SHA-256 patterns enforced by the CRD. More than 256 paths yields the
deterministic first 256, truncated=true, complete=false and ExplanationTruncated.
Over-budget individual ancestry/role chains are not fabricated as complete.
The serialized public explanation additionally stays below 192 KiB, keeping the
same deterministic prefix and marking truncation if long paths reach that budget.
Optional role discovery is bounded to 128 verified organizations; per group it
bounds roots/nodes to 512, edges/chains to 1,024 and depth to 32.
The aggregate role-binding evidence is limited to 1,024 chains. Cycles or excess
budgets become CompositeClosureIncomplete. No unlimited graph walk is permitted.

`complete=true` means the relevant supported provider observation/bindings are
resolved, all emitted portable origins are proven, no known native/unknown state
prevents a full structural account and nothing was truncated. It does not cover
all runtime subjects. Foreign/native policies remain untouched and visible;
provider-native extendChildren=true is never converted into Hanko ancestry.
Native permissions can also constrain the final result under Keycloak
provider-wide decision strategies; a managed structural alternative alone does
not promise a runtime allow. The real fixture demonstrates that distinction.
Native/unknown authorization may add other paths, so complete=false never means
that the displayed paths are the only ways to obtain access.

`AuthorizationExplained` is independent of Synced: True/Complete; False/Incomplete,
Truncated, Stale or ProvenanceReadUnavailable; Unknown/NotObserved when no usable
observation exists. Optional provenance read failure cannot invalidate otherwise
proven grants or cause policy writes. See the [read permission contract](../keycloak-permissions.md#optional-structural-role-provenance-reads).
Optional provenance reads have a 30-second aggregate deadline. Their failure
remains an explanation gap, not grant mutation or a new availability dependency.
Current uncached Kubernetes data, fresh exact group ownership, repeated role-edge
observations and final plan revalidation bound freshness. A concurrent dependency
change yields historical/stale or incomplete evidence rather than new applied
ancestry. Status updates do not trigger an explanation hot loop; indexed local
organization/role watches and periodic reconciliation refresh dependency changes.
Provider-only changes converge at the periodic interval.

Read/plan failure retains previous proven explanation as historical; its source
hashes/generation and the current condition disclose the distinction. Rename
keeps public Hanko refs; reparent changes ancestry only after verified successful
reconciliation. Role/composite paths change only after current provider reads.
Previously applied UUID grants can remain during failure or connectivity loss.
No instantaneous revocation, existing-token invalidation or application-enforcement
guarantee follows from an explanation. Incident response may require provider and
token/session revocation.

No usernames, email, user IDs, memberships, tokens, secret values/hashes, provider
UUIDs or raw payloads enter explanation paths. No user API, deny model, new CRD,
live Hub receiving schema or Continuum behavior is added. Status tampering does
not affect execution, adoption, ownership or deletion; new explanation is rebuilt
from provider evidence.

## Qualification and remaining limits

Unit/adversarial tests cover observed resource/action intersection, exact scope-only
coverage, overlapping alternatives, native/unknown gaps, deterministic order and
truncation, graph cycles/depth, forged and historical status and missing optional
reads. Kubernetes 1.35.0/1.36.2/1.37.0 qualifies bounded status admission/round-trip
and the existing quiescent dependency watcher. HTTPS Keycloak 26.7.5/26.8.0 qualifies
production-controller direct/descendant paths against actual UMA decisions,
realm/client mapping/composite origins, privilege failure, Observe, native-policy
preservation, rename/reparent and cleanup. The scanned-image installed system
qualifies a compact organization/descendant + overlapping role explanation.

Fine-grained group-only delegation, external IdP group population, provider/cloud
parity, portable backup/restore and live subject decisions remain unqualified.
The existing normal role grants and role-composition lifecycle remain unchanged.
