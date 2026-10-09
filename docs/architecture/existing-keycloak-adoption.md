# Existing Keycloak: explicit ownership adoption

Accepted direction for [RFC #46](https://github.com/Alien6-Studio/hankoshell-operator/issues/46),
starting milestone **0.5.0 — Adopt Existing Keycloak** after immutable v0.4.0.
This document defines the implementation contract. General adoption is **not
implemented** by this RFC. Current packaging remains 0.4.0, with 16 experimental
v1alpha1 CRDs. No package or 0.5 source tag is published.

## Decision

Accept target-local, one-shot **metadata annotation approval**. The future common
approval binds one target Kubernetes identity, one configured provider identity,
one complete semantic observation and one reviewed typed diff through a
versioned candidate hash. Its public annotation key/schema will be introduced
and validated by #48; this PR adds no executable annotation or API field.

HankoImport remains discovery/Observe orchestration. Import is not ownership.
Adoption first writes only ownership metadata/journal, verifies it from the
provider, and stops. **Enable Manage is a separate administrator decision** for
the common 0.5 path. No new CRD or central adoption authority is needed.

Preserve the existing application migration annotations unchanged:

```text
hanko.sh/migrate-keycloak-client-uuid
hanko.sh/migrate-keycloak-observation
```

They remain the existing compatibility path: exact UUID + complete observation,
fresh re-observation, owner-only marker, ownership read-back, then ordinary Manage
reconciliation in the same existing flow. They do not acquire a new diff
requirement retroactively. The new separate adopt/Manage phases must not silently
change this reviewed behavior. Status, an imported label, a name/clientID and a
similar-looking representation are never common adoption approval.

### Alternatives

| Mechanism | One-shot/Git review | Validation and generation | Cleanup/multiple objects | Compatibility/API cost | Decision |
| --- | --- | --- | --- | --- | --- |
| Target metadata annotations | One exact reviewable candidate, removable after success | Internally parse strict version/hash formats; fresh uncached metadata/spec reads and annotation-aware predicates, since annotation edits do not advance spec generation | Consume only after provider proof; aggregate membership stays target-local and is journaled remotely | Extends the application precedent without durable provider intent or another CRD | **Chosen** |
| `spec.adoption` on each kind | Reviewable but durable authority looks like desired state | Schema/admission typing and generation are stronger | A completed one-shot request needs explicit consumption; repeated blocks can appear reusable | Changes many alpha schemas and mixes migration with ordinary intent | Rejected for this one-shot contract |
| Dedicated HankoAdoption | Independent lifecycle could help cross-target transactions | Separate schema, admission, target/UID authorization and races | Adds delegation/cleanup coordination; still no provider transaction | 17th CRD and additional graduation burden | No independent authority requirement demonstrated |
| HankoImport-controlled adoption | Bulk import could hide individual authorization | Central authority must bind every target and provider child independently | Easily confuses inventory completion with write ownership | Breaks the current discovery boundary | Rejected |

## Current source inventory, not future support

The inventory follows controllers/adapters, not only their comments. **Observe**
below means today's controller behavior, not complete discovery of arbitrary
provider-native state. Import means generation of Kubernetes inventory objects;
HankoImport's Applied count does not prove provider application or ownership.

| Resource | Discover / import today | Observe today | Stable provider identity | Ownership / status-ID behavior today | Candidate 0.5 adoption |
| --- | --- | --- | --- | --- | --- |
| Realm | HankoImport lists available realms and creates HankoRealm | imported-by label forces read-only presence/display/theme/SMTP condition observation; no explicit mode | Internal realm `id`, with mutable URL realm name separate | Manage updates an existing named realm without a provider UID owner gate; finalizer can delete the realm and contents; status is not a new approval contract | **Arbitrary existing realm lifecycle stays Observe-only** |
| Application OIDC SPA/web/M2M | Non-internal OIDC clients imported; service-account-enabled clients normally classified as HankoServiceAccount | Explicit Manage/Observe; imported label forces Observe; normalized application observation is bounded to modeled semantics | Client UUID + realm UUID/provider instance; clientID is a lookup | `hanko.sh/application-owner` UID; existing exact UUID/observation migration; fresh marker required for writes/deletion; mapper IDs are lookup hints | First leaf candidate; preserve legacy syntax |
| Application SAML | HankoImport discovers/counts but refuses SAML generation, with unsupported finding | Explicit protocol-aware Observe/Manage works for the qualified subset | Client UUID + protocol/SP entity | Same application marker and migration guard; protocol mismatch/conversion refused | Design SAML inventory and same exact-state approval; implementation follows |
| ServiceAccount | OIDC service-account clients generate imported HankoServiceAccount | imported label means presence-only Observe, no secret read/rotation/finalizer deletion | Client UUID exists; current SA declaration uses realm/clientID | Cross-kind Kubernetes winner/protected-client checks; no equivalent provider UID client owner gate; existing named client can be used, secrets recovered, and Manage deletion resolves by clientID | Require kind-discriminated provider owner envelope and explicit compatibility migration before generic adoption |
| Realm Role/composites | Provider helpers list/read roles/closure; HankoImport does not generate HankoRole | imported label selects Observe in role IAM driver; no explicit spec mode | Role UUID + container realm identity | Exact singleton `hanko.sh/role-owner` UID; unmarked role conflicts, no public adoption workflow; status ID supplies no ownership | Owner-only leaf adoption; do not reconcile composites during acquisition |
| Client roles | Application helpers read/create/repair descriptions; no import role inventory | Observed as application roles, not standalone HankoRole | Role UUID + client UUID | Part of application management; no independent common acquisition/journal of every old role | Explicit child classification/selection; preserve UUIDs/composites, no standalone client_role CRD |
| Organization structural group | Group helpers exist, no HankoImport coverage | No common Observe mode today; imported label is not an organization safety switch | Group UUID + exact hierarchy | Name/namespace/UID attributes; strict existing-group check. Legacy-ID helper/preflight compatibility exists, but current reconcile does **not** pass LegacyOwnedID into EnsureGroup; deletion requires current markers | Exact group candidate, hierarchy and mappings covered; marker-only acquisition |
| Root native Organization | Alias lookup/read helpers, no HankoImport coverage | No independent Observe inventory | Organization UUID; alias/name are not ownership | Same name/namespace/UID tuple; strict EnsureOrganization does not receive LegacyOwnedID; old OrgID is only a limited preflight compatibility hint | Optional second object in the same target's checkpointed adoption; feature must already be enabled |
| ResourceServer authorization graph | Native scopes/resources/policies/permissions observed by adapter, not imported | Manage/Observe plus imported label; normalized graph and native findings, not every arbitrary representation | Backing client UUID + explicit child UUID graph | Client attribute `hanko.sh/resource-server-ownership`: bounded version/ownerUID/selected object journal, authoritative over status IDs; same audience/clientID insufficient | Selective aggregate only after backing application ownership, complete graph/foreign-boundary diff and exact selected IDs |
| IdentityProvider | HankoImport captures brokers as HankoRealm nested spec; suffix-based sensitive-config removal | Imported realm does not reconcile brokers; no individual full broker Observe contract | Raw provider has internalId; current typed projection omits it and uses alias | Realm Ensure upserts by alias, no common provider owner marker; managed-alias status participates in stale deletion | **Opaque broker aggregate remains Observe-only**, pending a separate credential/native ownership strategy |
| IdP mapper | Imported under realm broker; no separate target CR | Lists through imported discovery/application observation | Mapper UUID + exact broker internalId/realm | Realm path upserts by name and tracks IDs in status; application path uses `hanko.sh/application-owner` in mapper config and verifies UID before cleanup | Explicit child of a target application/approved supported aggregate, not adoption by name or realm status history |
| Application protocol mapper | Read by application adapter; HankoImport does not reconstruct typed token claims | OIDC application Observe includes mapper semantics; SAML qualified subset does not claim arbitrary mapper support | Mapper UUID + client UUID | Application UID marker in config, fresh provider check before deletion; legacy named approved mappers retain IDs. SA token-claim path lacks the same UID boundary | Preserve existing behavior; selective child approval, qualified types only |

Sources: [import](../../internal/controller/hankoimport_controller.go),
[realm](../../internal/controller/hankorealm_controller.go),
[service account](../../internal/controller/hankoserviceaccount_controller.go),
[application driver](../../internal/applications/keycloak.go),
[client owner/update primitives](../../internal/keycloak/applications.go),
[role driver](../../internal/roles/keycloak.go),
[organization](../../internal/controller/hankoorganization_controller.go),
[authorization journal](../../internal/keycloak/authorization_ownership.go).

HankoImport is one-shot: Done/Failed is terminal. It generates Observe inventory,
skips built-in/protected clients and already governed client identities, and never
calls provider mutation/credential routes. Its current broker sanitization is a
**key-suffix heuristic**, not a complete arbitrary-native credential classifier.
Unknown opaque configuration therefore cannot become an approvable general
candidate. #47 replaces broad inferred config coverage with typed, reviewed
secret-free observation/classification. SAML, roles, group/organization inventory,
authorization and organizational grant graphs are current import gaps. Workload
runtime binding consent/ServiceAccount/target intent cannot be inferred from IAM.

## Lifecycle and distinct authority

```text
DISCOVER → OBSERVE → PLAN → DIFF → APPROVE → ADOPT → VERIFY OWNERSHIP → MANAGE
```

| Phase | Meaning | Authority |
| --- | --- | --- |
| Discover | Identify objects and portable/native/unknown families; names are inventory | Provider reads only; no ownership or credential export |
| Observe | Independently reproducible normalized semantics, stable identities, ownership classification, child graph/coverage | Bounded reads only; no imported ID becomes authority |
| Plan | What this target could manage, which fields/children and provider capability limitations | Local computation only |
| Diff | Typed equal/manage/change/preserve/native/unsupported/credential/recreation/ownership entries | Review evidence only, not raw JSON or executable provider instructions |
| Approve | Administrator approves one complete candidate on one exact target | Explicit one-shot ownership acquisition authority; no self-grant or implicit future Manage |
| Adopt | Re-observe, recompute identities/diff and check exact approval; write markers/journal only | Smallest supported owner mutation, no drift repair/credential rotation/hierarchy/membership/protocol change |
| Verify ownership | Fresh read-back of every required marker/receipt and selected provider UUID | Proves acquisition; acknowledgement/status alone cannot advance it |
| Manage | Separate later explicit request activates the reviewed ownership/field boundary | Normal validated plan/ownership/freshness controls; not arbitrary provider lifecycle authority |

Future explicit Observe/Manage semantics should be standardized across adoptable
resources in #48, with safe defaults and compatibility admission tests. Ordinary
Observe remains write-free. An explicitly approved adoption is a separate
authorized phase, not an incidental side effect of Observe reconciliation.

For imported inventory, retain `hanko.sh/imported-by` as a read-only latch.
Successful adoption does not remove it or enable Manage. The administrator later
requests Manage and removes the label; the controller requires verified exact
ownership before honoring that transition. If both are requested before
acquisition is proven, refuse Manage. Preserve import provenance in bounded
evidence without treating a status flag as proof.

Selected child IAM resources must be manageable inside an externally provisioned
Observe realm **without acquiring realm deletion/runtime ownership**. Today role
and ResourceServer controllers have blanket restrictions under imported realms;
#49 must replace those restrictions with explicit qualified child boundaries.
Removing the realm's imported label is not the proposed workaround.

## Candidate, diff and approval identity

Conceptual internal envelope (not a new API struct in this PR):

```text
AdoptionCandidate {
  ContractVersion
  TargetIdentity       // kind, namespace, name, immutable Kubernetes UID
  ProviderIdentity     // configured instance/trust context, realm UUID, object UUID(s)
  ObservationHash
  DiffHash             // includes desired semantics and selected field/object boundary
  Complete
  CandidateHash
}
```

Provider identity includes the configured trusted installation, not just a
display name, endpoint string or realm/client lookup. Bind the operator's local
provider instance identity/endpoint/trust selection and observed realm UUID;
individual domains add client, role, group, Organization or mapper UUID/container
identities. ResourceServer binds the client plus the selected and relevant foreign
graph. Discovery may expose bounded non-secret provider IDs for administrator
review; user IDs/memberships and credentials never belong in this envelope.

Use existing `iamcontract.Hash` and canonical typed domain bytes. Purpose domains
are `adoption-observation`, `adoption-diff` and `adoption-candidate`, with an
explicit adoption contract version inside the IAM contract. CandidateHash binds
kind/target UID, provider identity, ObservationHash, DiffHash and version.
Equivalent sets/order hash identically. Reviewed graph/field, desired spec,
protocol, provider UUID, target replacement or owner changes invalidate approval.
Use current uncached Kubernetes/provider reads and recompute rather than copying
hashes from status. Annotation changes need a dedicated watch predicate and
fresh metadata digest; generation alone is insufficient.

Administrators review the visible target/provider identities, coverage, typed
diff, selected ownership boundary, credential/native exclusions and later Manage
effects before approving the candidate hash. The hash is not an unexplained
permission token and cannot authorize another target/kind/provider. Consumption
and remote receipt make it one-shot. Wrong identity/version/hash, truncation,
unknown required semantics, foreign owner or recreation requirements refuse
acquisition; status tampering never changes this result.

### Typed diff and native categories

| Diff code | Meaning and acquisition implication |
| --- | --- |
| equal | Represented managed semantics already match |
| would-manage | Exact supported field/object selected for future ownership |
| would-change | Non-destructive drift repair after separate Manage; explicitly reviewed, not executed during acquisition |
| would-preserve | Foreign/additive semantics outside ownership stay untouched |
| provider-native-readonly | Known native state observed/classified but not managed |
| unsupported | Required coverage/behavior cannot be proven; candidate not approvable |
| credential-excluded | Field presence/reference classification only; never value or value-derived hash |
| recreation-required | Protocol conversion, object/realm replacement, hierarchy/membership migration or credential rotation is not ordinary adoption |
| ownership-transition | Exact currently unmarked object receives the target's marker/receipt only |

Native findings use stable local codes and bounded typed object/field references:
supported typed native, preserved read-only native, unsupported, conflicting,
and security-sensitive excluded. Reuse IAM lossless/lossy/unsupported findings
where compatible, rather than a raw JSON or arbitrary string policy language.
The common findings vocabulary for implementation is `AdoptionApprovalRequired`,
`AdoptionObservationChanged`, `AdoptionIdentityChanged`,
`AdoptionOwnershipConflict`, `AdoptionDiffChanged`, `AdoptionIncomplete`,
`AdoptionUnsupported`, `AdoptionRequiresRecreation`, `CredentialExcluded` and
`NativeStatePreserved`. These are bounded semantic reasons, not provider error
text; #47/#48 will add the executable contract and tests.
Round-trip levels are **lossless represented state**, **preserved native outside
ownership**, **lossy** and **unsupported**. Required loss refuses ordinary
adoption; no allowLossy switch is accepted. `would-change` is not permission for
loss of foreign configuration.

The current application **owner-only** primitive preserves unknown attributes,
but subsequent `UpdateApplication` owns most of the attributes map, apart from
the ResourceServer journal. Its existing observation is modeled, not a complete
fingerprint of arbitrary client extensions. General 0.5 candidates must classify
the additional native fields/children and expose any later erasure; #49 must
prove preservation before enabling Manage. Do not advertise the legacy migration
hash as complete native adoption coverage.

SAML inventory must distinguish the qualified unsigned-SP-request POST subset
from native request-signing certificates, encryption, artifact/ECP bindings,
attribute mappers and other unsupported extensions. A client created with
Keycloak's request-signing defaults can retain `saml.signing.certificate` and
fail ordinary Hanko read-back equality even after an approved owner transition.
The positive migration probe explicitly disables client-request signatures;
it does not establish lossless general SAML adoption. #47/#49 must classify and
preserve these native differences or keep the candidate non-approvable.

### Bounds and completeness

Accepted initial limits for #47: 16 explicitly selected realms, 1,024 inventory
candidates per run, 512 graph nodes/1,024 edges per candidate, 32 hierarchy/role
edges, 256 typed diff entries, 32 findings and 192 KiB serialized public candidate
summary. IDs are at most 128 bytes; ordinary references 255, locally authored
codes/messages at most 512. Existing domain/journal budgets remain lower where
applicable: 64 scopes, 64 resources, 256 policies and 128 permissions. Provider
pagination, read timeouts/byte limits and aggregate deadlines must also fail
explicitly on incomplete coverage; never certify just the first page.

Sort by domain/object identity, field code and semantic value; normalize
unordered sets. Over-budget evidence keeps a deterministic bounded diagnostic
prefix with incomplete/truncated findings. It cannot be approved. Complete means
all relevant supported semantics and foreign graph boundaries were covered and
classified, not every provider byte or runtime subject. Opaque credentials are
intentionally excluded: public hashes cannot detect secret-byte rotation and
do not approve it. If safe owner acquisition depends on opaque content or an
unproven partial update, remain unsupported/Observe-only.

## Ownership recipes and recovery

| Domain | Ownership-only first mutation | Required post-write proof / limit |
| --- | --- | --- |
| Application | Existing client UID attribute plus future compatible candidate receipt; no secret field in PUT | Exact client UUID/protocol/current owner and preserved selected/native graph; preserve old UID marker meaning |
| ServiceAccount | Separate kind-discriminated client envelope with UID/version/candidate receipt | Never interpret an application marker as SA ownership; contradictory/mixed markers conflict; protected clients remain refused |
| Role | Merge exact singleton role UID attribute plus receipt into existing attributes | UUID, description, native attributes and direct/effective composites unchanged |
| Organization | Merge current name/namespace/UID attributes plus receipt into exact group and optional native Organization | All expected UUIDs/parent boundaries read back; additive mappings/foreign children remain outside acquisition |
| ResourceServer | Merge bounded selected-object journal/receipt into already owned backing client | Exact selected IDs and complete incoming/outgoing graph boundaries; preserve foreign/native policies/resources/permissions |
| Application-owned mapper | Merge existing application UID config marker/receipt on one exact child UUID | Same type/config/parent UUID; no name-based replacement or acquisition of every mapper |
| Realm / opaque IdP aggregate | No accepted general lifecycle acquisition recipe in 0.5 | Observe-only, despite experimental marker representation round-trip |

Remote receipt binds target kind/UID, contract version and approved candidate to
the expected object set. It is an ownership checkpoint, not an executable plan.
Multi-object adoption records the same set/receipt at each checkpoint. If only
the group marker is written, adoption remains partial: no Manage, deletion,
hierarchy repair or automatic rollback. Retry verifies exact already-owned
members and re-observes unmarked members against the approved candidate. It
never borrows ownership from a similarly named replacement or overwrites a
foreign/partial/malformed marker.

| Failure | Safe retry |
| --- | --- |
| Owner write succeeded, HTTP acknowledgement lost | Read first; prove exact receipt/identity and semantic boundary; no unconditional repeat or Manage |
| Owner write succeeded, Kubernetes status patch failed | Reconstruct evidence from provider marker/journal; status is not authority |
| Group owned, native Organization denied/failed | Retain partial checkpoint, show failure, retry only the missing proven member |
| Child/UUID/desired diff/provider context changed | Previous approval invalid; request a newly reviewed candidate |
| Foreign owner appears at a fresh checkpoint | Ownership conflict; no overwrite |
| Read-back/coverage unavailable | Keep historical evidence, acquisition unproven, no semantic writes/deletion |

Keycloak's qualified PUT endpoints do not provide a proven atomic
compare-and-swap transaction across the read/write sequence or objects. Fresh
checks, local single-writer coordination and post-write comparison reduce but do
not eliminate external administrator races. Provider administrators are trusted
for markers and must serialize ownership/configuration edits during acquisition.
No linearizable multi-object transition is claimed. Concurrent changes visible
at checkpoints fail closed; stronger conflict guarantees require a qualified
provider primitive, not another status flag. Fault-injected acknowledgement and
status recovery of the future executor remain #48/#49 acceptance requirements;
the RFC probes only primitive read-back/no-op/partial-state behavior.

Ownership does not automatically justify deletion: deleting a group cascades
children and deleting a realm cascades foreign contents. Shared authorization
scope/resource/policy references can also affect unowned objects. Future cleanup
must freshly prove ownership **and** absence of foreign incoming dependents or
refuse destructive changes. Acquiring a selected graph subset never acquires the
entire client, realm, descendants or membership population.

## Secrets and least privilege

Discovery/Observe/diff/adoption never calls client-secret routes to inventory
clients and never exports client/SA/IdP secrets, tokens, passwords, private keys,
admin credentials or hashes derived from their values. This applies to spec,
status, findings, Events/logs and any future bounded Hub evidence. Sensitive
native values are excluded before canonicalization. A credential reference is
not proof that the operator knows or should retrieve the credential.

Existing post-adoption Manage credential recovery/rotation/projection retains
its separately qualified authority. The RFC client probes validate known
disposable credentials through authentication, without an inventory secret read.
Opaque IdP config is masked by Keycloak; accepting an extra config key and
preserving that representation does not prove a live broker login or hidden
credential preservation. Future broker management requires administrator-supplied
Secret references and a qualified safe update/journal strategy; never copy a
provider secret into Kubernetes.

| Evidence family | Qualified read-only role | Isolated marker/update role |
| --- | --- | --- |
| Realm identity and realm roles/composites | view-realm | manage-realm |
| Client, client roles and protocol mappers | view-clients | manage-clients |
| Authorization graph | view-clients + view-authorization | manage-clients |
| Groups, hierarchy and role mappings | view-users | manage-users |
| Native Organization | view-organizations | manage-organizations; enabling feature separately requires manage-realm |
| Broker and IdP mappers | view-identity-providers | manage-identity-providers |

All grants are target-realm delegated roles, not master/global/realm-admin.
view-users includes user reads, not group-only delegation. On **26.7.5**,
view-clients can also expose confidential client secrets; on **26.8.0** the
already-qualified client-secret route requires manage-clients. A mutation-read-only
inventory identity is therefore not credential-confidential on 26.7.5. The
operator must avoid the route, but that does not remove the identity's residual
authority. See [the permission guide](../keycloak-permissions.md).

Today the production HankoImport uses the shared default Pool client when
configured, bypassing the sourceRef credential-building branch; it does not
automatically select an isolated read-only account. #47 must make the inventory
identity/source selection explicit. Existing import RBAC comments include Secret
get/list/watch; direct source adminRef/private CA construction needs named get,
while the shared cached client/other controllers also require review. Record the
cache/watch and chart-wide implications before narrowing, with no unrelated RBAC
change here.

## Real provider characterization

Committed [characterization fixture](../../internal/controller/keycloak_adoption_characterization_test.go)
uses the existing digest-pinned, verified private-CA HTTPS Keycloak **26.7.5 and
26.8.0**. Bootstrap provisions disposable objects/roles only. Dedicated inventory
and isolated per-domain writer service accounts perform observations and probes.
Inventory PUTs are denied. Its TLS route recorder rejects every Admin mutation
and client-secret path while exercising actual HankoImport.

```sh
make keycloak-integration-test KEYCLOAK_VERSION=26.7.5
make keycloak-integration-test KEYCLOAK_VERSION=26.8.0
```

The focused test is `TestRealKeycloakAdoptionCharacterization`; existing
`TestRealKeycloakLegacyApplicationMigration` and protocol/flow qualification
remain regression evidence for UUID/hash approval, wrong/forged/foreign state,
credential/mapper/role preservation and protocol recreation rules.

| Probe | Both qualified versions / meaning |
| --- | --- |
| SPA/web/M2M/SAML client owner-only operation | Stable UUID/protocol/non-secret fields, native attributes, role/mapper IDs; known confidential credentials still authenticate; wrong owner cannot delete |
| Existing qualified SAML approval | Unmarked client requires exact UUID/complete observation; material change invalidates approval; fresh approval preserves UUID and protocol. Native request-signing defaults are outside this positive fixture |
| Realm role attribute marker | Stable UUID/description/native attributes and direct/effective composite graph; no-op read-back; deleting root preserves composite child roles |
| Existing group + nested child + mappings | Marker-only PUT preserves hierarchy/mappings; deleting group cascades child, so foreign child cleanup is unsafe |
| Root native Organization | Attribute marker/UUID/alias/domains round-trip; inventory denial after group checkpoint leaves partial state; retry no-op; native Organization deletion preserves separate structural group |
| Realm | Internal UUID/attribute marker round-trip and clients preserved by marker; deleting a separate disposable realm removes its unrelated child client; lifecycle adoption declined |
| OIDC broker and IdP mapper | Broker internalId/config marker representation round-trip with opaque credential excluded; mapper UUID/config marker round-trip; mapper deletion preserves broker; live broker credential/login semantics unqualified |
| ResourceServer selective journal | One selected scope journal preserves foreign resource, role/aggregate native policy and permission graph; no blanket graph claim; isolated scope delete preserves native graph |
| Actual HankoImport | Read-only credential identity, no Admin mutation or client-secret route; imported apps remain Observe, SAML remains a visible generation gap, known credential values absent from inventory/status |

These are primitive feasibility/limits, not qualification of a new production
adoption executor, all IdP extensions, arbitrary native fields, membership
migration or portable rollback. No users/member API, LDAP sync, live Hub plan
transport or Continuum change is introduced.

## Implementation backlog and order

1. [#47 — bounded discovery, observation and adoption diff](https://github.com/Alien6-Studio/hankoshell-operator/issues/47): expanded typed inventory, canonical secret-free candidates/diff, coverage/bounds and practical read-only identity/RBAC review. No adoption authority.
2. [#48 — explicit provider ownership adoption](https://github.com/Alien6-Studio/hankoshell-operator/issues/48): annotation approval and leaf owner-only transitions, kind-safe SA marker, legacy application compatibility, separate Manage, fault/replacement/tamper qualification.
3. [#49 — aggregate adoption, native preservation and adopt-to-manage](https://github.com/Alien6-Studio/hankoshell-operator/issues/49): organizations/ResourceServer checkpoints and foreign dependencies, selected children in external realms, native preservation during Manage and exact-image end-to-end qualification.

After those implementations, qualify exact protected main before considering a
0.5 source freeze. This RFC closes only #46 after protected review/merge; the
implementation issues and milestone stay open. v0.1/v0.2/v0.3/v0.4 remain immutable
and production publication remains independent in #21.
