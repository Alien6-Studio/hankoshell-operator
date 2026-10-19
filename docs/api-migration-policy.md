# API conversion, migration and rollback policy

This policy describes the current development schema and required review for its
evolution. The [#81 candidate selection](public-contract-selection.md) and its
[frozen corpus](public-contract-semantics.md) define the initial qualification
scope; activation still requires qualification and first publication. There is no published 0.x
predecessor, stable API version, conversion webhook or qualified cross-release
rollback matrix. Tests of one development revision must not be described as
N-1 → N public-release compatibility.

## Stored API and conversion

The 17 CRDs remain experimental. Application, Role and ResourceServer now
serve **v1alpha1 and v1beta1**; the other 14 serve only v1alpha1. The default hub
and storage version remain v1alpha1 for every CRD. This technical beta candidate
does not ratify the stable resource contract or change release metadata.

The [conversion decision](api-conversion.json) requires identical complete
structural schemas, defaults, validation, list topology, subresources and
selectors in both versions. Kubernetes conversion `None` changes only the root
apiVersion. The beta Go package uses the alpha Spec/Status types and explicit,
independent deep-copy conversions, including lists. UID, owner-reference versions,
approvals, provider journals and field managers retain their meaning. Divergent
schemas or a new version require a new conversion design; this mechanism cannot
implement renames or semantic transformations.

The [executable development contract](go-api-contract.md) guards the Go surface
and schema fingerprints. Real API fixtures exercise every served version through
the opposite typed reader; native storage qualification uses the administrator
command and actual etcd encoding. See the [storage migration runbook](storage-migration.md)
for plan approval, native migrator prerequisites, interruption recovery, rollback
and CRD upgrade preflight. No operator or chart installation automatically flips
storage. The migration command deliberately refuses active rotation/delegation
configurations whose native transaction state cannot be proven idle from CR status.

Within the development version, prefer additive optional fields. Any new required
field, tightened validation, default change, list/map topology change, pruning,
rename or removal needs a migration analysis, explicit fixture update and
rollback limitation in the same PR. Do not call an optional addition safe until
old stored objects and readers are checked. Admission validation and read-time
defaulting alone do not prove stored bytes have been rewritten.

Any further served/storage version requires an explicit conversion decision,
round-trip fixtures preserving supported meaning, a storedVersion inventory,
restartable migration and a reviewed rollback matrix before changing storage.
Do not remove an old served version or edit CRD status.storedVersions to pretend
that stored objects have migrated. Deprecation and removal require an announced
replacement and an explicit compatibility decision; this policy does not promise
that the current experimental API will become stable unchanged.

## CRD and operator ordering

Use a reviewed exact source revision and immutable operator image. For an existing
installation:

1. Inventory the installed CRDs, storage versions, active operations, approvals,
   journals and field managers. Keep necessary private recovery material in
   approved encrypted storage outside Git, logs and public artifacts. Do not
   collect token/credential values into compatibility fixtures.
2. Read the change's resource-specific migration notes. Suspend affected
   reconciliation and any competing writer before changing authority, list
   topology or an unreadable journal; use one active operator writer.
3. Apply the reviewed CRDs explicitly, and wait for their Established condition
   before applying new fields or starting the new operator. Helm's `crds/`
   installation mechanism does not perform CRD upgrades or downgrades; an ordinary
   `helm upgrade`/`helm rollback` is not a schema migration. See the
   [Helm CRD lifecycle](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/).
4. Upgrade the operator/chart, then resume only the reviewed controllers. Verify
   current-generation status and actual provider observations, ownership UIDs,
   journal readability and runtime output identity. A historical Ready condition
   is insufficient.

Never delete/recreate a CRD as an upgrade technique: that can delete its stored
custom resources and change ownership identities.

## Conditions list migration

All status `conditions` lists, including nested application mapper conditions,
are keyed by `type` (`listType: map`, `listMapKey: type`). Different SSA managers
can own different top-level condition types; a conflicting change to the same type
must still fail. Nested mapper conditions retain the existing ownership topology
of their containing lists; type keys alone do not make those outer lists granular.
This does not grant a GitOps identity access to the status subresource or convert
existing controller merge patches into SSA.

Before applying this schema to an older development installation, stop affected
status writers and inspect existing top-level/nested lists for duplicate types.
Resolve duplicates through the responsible writer after reviewing their meaning;
do not clear operational checkpoints or replace the entire status to pass
validation. Kubernetes cannot infer per-entry ownership when an atomic list
becomes a map. Re-establish intended field ownership through the responsible
manager under the new schema and verify read-back before resuming competing
writers. Do not treat the absence of a first conflict as authorization. See
[Kubernetes topology changes](https://kubernetes.io/docs/reference/using-api/server-side-apply/#compatibility-across-topology-changes).

The API fixtures on Kubernetes 1.35.0/1.36.2/1.37.0 verify the new-schema merge,
same-type conflict and duplicate rejection for all 17 CRDs. They do not perform
an installed old-schema migration or prove ownership transfer for old managedFields.
Rolling back to atomic lists can turn entry ownership into whole-list conflicts;
keep the reviewed newer CRD where the older reader is proven compatible, or keep
writers suspended until a tested downgrade procedure exists. Do not strip
managedFields or force ownership globally to conceal a conflict.

## Ownership, journals and approvals

Persisted formats have independent identities; a plan hash is not an executable
plan or a signature. The current format families include:

| State | Current identifier / boundary | Reader and rollback rule |
| --- | --- | --- |
| IAM plan evidence | `hanko.sh/iam-contract/v1alpha1` | In-process plans must be recompiled; serialized hashes cannot authorize execution. |
| Adoption approval/receipt | `hanko.sh/adoption-contract/v1alpha1` | Exact target UID, source and reviewed candidate bind authority; changed identity requires a new review. |
| Application owner / service-account owner | `hanko.sh/application-owner`, `hanko.sh/client-owner-kind`, `hanko.sh/client-owner-uid` | Preserve the exact CR UID; an absent or foreign marker is not implicit adoption. |
| Realm role / resource server | `hanko.sh/role-owner`, `hanko.sh/resource-server-ownership` | Preserve owned provider IDs and the journal; old status alone cannot authorize cleanup. |
| Workload trust | `hanko.sh/workload-trust-journal/v1alpha1`, `hanko.sh/workload-trust-checkpoint/v1alpha1` | Require the recognized format and current source/owner binding. |
| Application runtime output | `hanko.sh/application-runtime/v1alpha1`, `hanko.sh/runtime-bindings-journal` | Preserve target UID/consent and owned fields; no blind projection replay. |
| Workload runtime output | `hanko.sh/workload-runtime/v1alpha1`, `hanko.sh/workload-runtime-journal` | Preserve workload and ConfigMap UIDs; no token or Pod mutation authority follows from metadata. |
| Service-account rotation | `hanko.sh/service-account-rotation/v1alpha1` | Inspect pending native and Secret cutover before downgrade; do not restart a transaction from an empty status. |
| Image approval | Administrator policy purpose + exact digest/source/publisher | Preserve purpose-specific verification; a chart or controller downgrade cannot substitute another approval. |
| Snapshot / operation | Persisted intent, source UID/generation, child UID/generation and capture hash | Reconcile only the recorded intent; never clear checkpoints to force replay. |

This is an inventory of implemented formats, not a promise that every older
development reader understands them. Before introducing a new persisted format,
declare which old/new readers accept it, how unknown versions fail closed and how
partially completed transactions resume. Unknown or unqualified forward state
requires suspended management and administrator review, not a speculative rewrite.
Marker/schema changes need a migration issue and fixtures; preserve existing
markers during unrelated reconciliation. No 0.x forward/backward readability
commitment is ratified by this development policy.

## Per-resource rollback boundaries

All rows use conversion `None`. Default storage is `v1alpha1`; the three beta
candidates may use `v1beta1` only after the approved native migration procedure.

| Resource | Required inspection before rollback |
| --- | --- |
| HankoRealm | Effective profile, managed identity providers and realm ownership; never delete a realm to undo a schema change. |
| HankoIAMProfile | Effective defaults and referencing realms; recompute policy evidence with the chosen reader. |
| HankoApplication | Client UID/owner, adoption receipt, mapper journals, runtime targets and pending credential rotation. |
| HankoRole | Role UID marker, adoption receipt and additive composites; preserve foreign roles and members. |
| HankoOrganization | Native organization/group identities, parent position and grants; preserve foreign descendants. |
| HankoResourceServer | Owned graph IDs, resource-server journal and dependent permissions before any cleanup. |
| HankoServiceAccount | Native authenticator transition, workload binding, rotation journal and Secret/runtime output UIDs. |
| HankoWorkloadTrust | Provider UUID, journal/checkpoint, source identity and complete dependent inventory. |
| HankoIssuer | Current declared host and observed public routing; this is not a certificate or ingress rollback. |
| HankoKeycloakInstance | TLS, admin capabilities, infrastructure owners and managedObservation; suspend managed operations before reverting guards. |
| HankoImport | Complete inventory, imported modes and provenance; an older reader must not resume unintended writes. |
| HankoSnapshot | Immutable capture/hash, child Job UID and tenant scope; no portable restore guarantee. |
| HankoOperation | In-flight intent/children and actual provider effects; deleting a CR does not undo those effects. |
| HankoTheme | Installed image, PVC, JAR path and owned build Job; older code must not overwrite or delete foreign workloads. |
| HankoTenant | Enrolled identity, token transaction and bundle ownership; retain disconnected recovery evidence. |
| HankoMeshService | Registered workload/Service UIDs, projected policy and connected state; audit-only projection is not enforcement. |
| HankoEmailProvider | Deprecated no-delivery behavior and legacy fields; rollback must not imply a resumed mail adapter. |

Rolling back the operator does not roll back Keycloak, data, credentials, CRDs,
runtime outputs or external effects. Keep affected writers suspended if the older
reader cannot prove authority and understand pending state. Inspect and preserve
foreign resources rather than adding ownership to make an old reader accept them.
Existing detailed [migration notes](secure-deployment.md#upgrade-and-rollback)
remain authoritative for their specific transitions.

#84 must add exact released-schema round trips and installed upgrade/rollback
proof once actual predecessor versions exist. #86 must bind that evidence to the
candidate. No tag, release, package or production trust is created by this policy.
