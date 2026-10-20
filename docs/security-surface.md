# CRD validation and RBAC review inventory

Development checkpoint for #99, with compatibility/runbook guard work for
#94/#103. The [machine inventory](security-surface.json) records every served
schema hash, declared string/array/typed-map bounds, rendered Role/ClusterRole
rule, binding and mandatory admission policy on six reviewed chart profiles,
including configured sensitive outputs and projection creation. It is not stable-contract
acceptance or an independent security audit.

The inventory contains **1,343 declared fields/collections across 20 served schemas**.
**No inventoried string, list or typed map lacks an explicit maximum** (finite
string enums count as bounded). These size controls are not an independent
security review or proof of provider convergence. Opaque provider extensions,
field semantics and inherited Kubernetes schemas still need contextual review.
Status is inventoried along with spec.

Every inventoried `spec` string, list and typed map now has an explicit maximum.
The inventory rejects future spec/status gaps rather than recording them as an accepted
baseline. Integer-or-string resource quantities also have a 64-character bound,
and native attribute/configuration map keys require 1..255 characters.

## Admission changes and migration notice

This unpublished alpha contract now enforces 1..253-character Kubernetes-name
references on `spec.realmRef` in HankoApplication, HankoRole,
HankoResourceServer, HankoServiceAccount, HankoOrganization and HankoIssuer,
and on HankoResourceServer `spec.applicationRef`. HankoWorkloadTrust already
had the same length bounds and remains in the common admission fixture.
References reject paths, uppercase, empty labels and control characters. The
issuer retains its existing narrower single-label pattern; this change does not
widen it. These are Kubernetes object references, not provider-native realm or
client identifiers. They do not add a stable API version or move storage.

Before applying the updated CRDs, inspect stored references and correct invalid
ones through the normal reviewed resource change procedure. Existing objects
are not rewritten or deleted; later writes that retain invalid values may be
refused. Test a saved manifest with `kubectl apply --dry-run=server -f MANIFEST`
against the candidate API before changing the installation. Do not rename a
provider realm, re-adopt a client, drop a CRD or remove finalizers to clear a
validation error. This notice updates the three frozen **development** schemas;
there is no published predecessor or stable deprecation exception.

`checkBoundedReferences` exercises eight fields, legal 1/253-character boundaries,
empty/254-character/path/uppercase/empty-label/trailing-dot/hyphen/control cases
on all supported Kubernetes API servers. These dry runs qualify admission,
not referent existence or provider writes.

## Leader-lock reduction

The main namespace Role now grants `leases/create` and exact-name
`leases/get,update` for `hanko-operator.hanko.sh`, matching managerOptions and
client-go's LeaseLock. It no longer grants list/watch/patch/delete on leases.
Kubernetes RBAC cannot constrain CREATE by resourceNames: creation remains
namespace-wide and is not presented as name-isolated. `checkLeaderLeaseRBAC`
uses the real client-go lock to create/read/renew under the rendered Role,
then proves foreign reads/writes, listing and even owned-lock deletion forbidden.

## Rendered grants and their review rationale

Each row below records all its verbs. This is an executable drift baseline and
an assessment of current purpose, not a proof that every broad grant is minimal.
Secret/Deployment writes now require exact administrator targets and mandatory
fail-closed admission. The complete admission specs/bindings are also frozen in
the JSON, so changing a predicate or switching Deny to Audit causes drift.
Credential inputs retain uncached namespace-local get; no default list/watch.
Other namespace-local ConfigMap/Service/Job authority remains part of the
administrator-trusted operator namespace. A CR author is not a hostile-tenant
isolation boundary; use separate operator namespaces/credentials where needed.

Profiles: `standard`, `without-lifecycle`, `with-lifecycle`, `cilium`,
`connected-with-grants`, and `with-sensitive-targets`. The latter covers exact
local output/rotation/provider names and both existing-only and create-approved
cross-namespace projections. Bindings and their exact subjects are in the JSON.
See [configuration and migration](secure-deployment.md#exact-secret-and-deployment-write-authority).

| Profiles | Role / namespace | API group / resources | Names | Verbs | Purpose / residual limit |
| --- | --- | --- | --- | --- | --- |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | core,events.k8s.io / events | all in scope | create, patch | Record reconciliation Events through both Kubernetes Event APIs; no list/read/delete. |
| with-sensitive-targets | Role security-review-hanko-operator / auth | core / secrets | hanko-app-reviewed, reviewed-admin-rotation | patch, update | Administrator-approved exact credential/projection targets. Updates and patches are name-scoped; mandatory fail-closed admission constrains CREATE to those same namespace/name pairs and Opaque data, forbidding ServiceAccount token minting. Controller ownership and consumer UID consent remain required. |
| connected-with-grants | Role security-review-hanko-operator / auth | core / secrets | hanko-hub-token | patch, update | Administrator-approved exact credential/projection targets. Updates and patches are name-scoped; mandatory fail-closed admission constrains CREATE to those same namespace/name pairs and Opaque data, forbidding ServiceAccount token minting. Controller ownership and consumer UID consent remain required. |
| connected-with-grants, with-sensitive-targets | Role security-review-hanko-operator / auth | core / secrets | all in scope | create | Administrator-approved exact credential/projection targets. Updates and patches are name-scoped; mandatory fail-closed admission constrains CREATE to those same namespace/name pairs and Opaque data, forbidding ServiceAccount token minting. Controller ownership and consumer UID consent remain required. |
| with-sensitive-targets | Role security-review-hanko-operator-sensitive-projections / created-workloads | core / secrets | created-output | get, patch | Administrator-approved exact credential/projection targets. Updates and patches are name-scoped; mandatory fail-closed admission constrains CREATE to those same namespace/name pairs and Opaque data, forbidding ServiceAccount token minting. Controller ownership and consumer UID consent remain required. |
| with-sensitive-targets | Role security-review-hanko-operator-sensitive-projections / created-workloads | core / secrets | all in scope | create | Administrator-approved exact credential/projection targets. Updates and patches are name-scoped; mandatory fail-closed admission constrains CREATE to those same namespace/name pairs and Opaque data, forbidding ServiceAccount token minting. Controller ownership and consumer UID consent remain required. |
| with-sensitive-targets | Role security-review-hanko-operator-sensitive-projections / existing-workloads | core / secrets | existing-output | get, patch | Administrator-approved exact credential/projection targets. Updates and patches are name-scoped; mandatory fail-closed admission constrains CREATE to those same namespace/name pairs and Opaque data, forbidding ServiceAccount token minting. Controller ownership and consumer UID consent remain required. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | core / configmaps | all in scope | create, get, list, patch, update, watch | Fleet/checkpoint/runtime metadata and mesh projection; cross-namespace writers are named. Namespace-local dynamic names remain broad. |
| connected-with-grants | Role security-review-hanko-operator-mesh-policy / transport | core / configmaps | hanko-mesh-policy | get, patch, update | Fleet/checkpoint/runtime metadata and mesh projection; cross-namespace writers are named. Namespace-local dynamic names remain broad. |
| connected-with-grants | Role security-review-hanko-operator-transport-decommission / transport | core / configmaps | hanko-mesh-policy | delete, get | Fleet/checkpoint/runtime metadata and mesh projection; cross-namespace writers are named. Namespace-local dynamic names remain broad. |
| connected-with-grants | Role security-review-hanko-operator-workload-binding / workloads | core / configmaps | worker-identity | get, patch | Fleet/checkpoint/runtime metadata and mesh projection; cross-namespace writers are named. Namespace-local dynamic names remain broad. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | core / persistentvolumeclaims | all in scope | get, list, watch | Observe explicitly selected managed/theme storage; no volume writes. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | core / pods,serviceaccounts | all in scope | get, list, watch | Observe managed workload readiness and node identity; no Pod writes or exec. Observe workload identities; decommission patches only the release-owned account. No token minting. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | core / serviceaccounts | security-review-hanko-operator | patch | Observe workload identities; decommission patches only the release-owned account. No token minting. |
| connected-with-grants | Role security-review-hanko-operator-workload-binding / workloads | core / serviceaccounts | worker | get | Observe workload identities; decommission patches only the release-owned account. No token minting. |
| connected-with-grants | Role security-review-hanko-operator-transport-decommission / transport | core / secrets | all in scope | delete, get, list | Opt-in transport bookkeeping: namespace-scoped get/list/delete; mandatory admission limits deletion to configured exact Secrets or exact release name, namespace, Helm type/labels and versioned history prefix. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | ClusterRole security-review-hanko-operator-node-reader / cluster | core / nodes | all in scope | get | Read Pod.nodeName-derived node identity; names are discovered dynamically; no list/watch or writes. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | core / secrets | hanko-hub-enroll, hanko-hub-tls | delete | Read referenced credentials without caching, or delete exact release bootstrap/CA Secrets at approved decommission. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | core / secrets | all in scope | get | Read referenced credentials without caching, or delete exact release bootstrap/CA Secrets at approved decommission. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | ClusterRole security-review-hanko-operator-cluster-identity-reader / cluster | core / namespaces | kube-system | get | Read the exact kube-system UID used to bind this physical cluster. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | core / services | security-review-hanko-operator-metrics | delete | Reconcile managed provider Services, observe mesh egress endpoints, remove exact release metrics Service. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | core / services | all in scope | create, get, list, patch, update, watch | Reconcile managed provider Services, observe mesh egress endpoints, remove exact release metrics Service. |
| connected-with-grants | Role security-review-hanko-operator-mesh-egress-reader / egress | core / services | all in scope | get | Reconcile managed provider Services, observe mesh egress endpoints, remove exact release metrics Service. |
| with-sensitive-targets | Role security-review-hanko-operator / auth | apps / deployments | reviewed-provider, security-review-hanko-operator | patch, update | Read provider infrastructure; exact administrator-approved names permit creation/update. Mandatory fail-closed admission requires current Restricted Pod Security, preserves ServiceAccount bindings, and forbids API token mounting in provider Deployments. Only the named operator Deployment may be deleted. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | apps / deployments | security-review-hanko-operator | delete | Read provider infrastructure; exact administrator-approved names permit creation/update. Mandatory fail-closed admission requires current Restricted Pod Security, preserves ServiceAccount bindings, and forbids API token mounting in provider Deployments. Only the named operator Deployment may be deleted. |
| cilium, connected-with-grants, standard, with-lifecycle, without-lifecycle | Role security-review-hanko-operator / auth | apps / deployments | security-review-hanko-operator | patch, update | Read provider infrastructure; exact administrator-approved names permit creation/update. Mandatory fail-closed admission requires current Restricted Pod Security, preserves ServiceAccount bindings, and forbids API token mounting in provider Deployments. Only the named operator Deployment may be deleted. |
| with-sensitive-targets | Role security-review-hanko-operator / auth | apps / deployments | all in scope | create | Read provider infrastructure; exact administrator-approved names permit creation/update. Mandatory fail-closed admission requires current Restricted Pod Security, preserves ServiceAccount bindings, and forbids API token mounting in provider Deployments. Only the named operator Deployment may be deleted. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | apps / deployments | all in scope | get, list, watch | Read provider infrastructure; exact administrator-approved names permit creation/update. Mandatory fail-closed admission requires current Restricted Pod Security, preserves ServiceAccount bindings, and forbids API token mounting in provider Deployments. Only the named operator Deployment may be deleted. |
| connected-with-grants | Role security-review-hanko-operator-transport-decommission / transport | apps / daemonsets | continuum-continuum-vpn | delete, get | Read/delete only the configured transport release DaemonSet after decommission approval. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | batch / jobs | all in scope | create, delete, get, list, watch | Run/observe/clean approved theme/snapshot Jobs with dynamic names in the operator namespace. Mandatory admission requires current Restricted Pod Security, default/no ServiceAccount and explicit refusal of automatic/projected API tokens. Controller UID/checkpoint checks remain necessary. |
| cilium | Role security-review-hanko-operator / auth | cilium.io / ciliumnetworkpolicies | security-review-hanko-operator | delete, get | Read/delete the exact optional release Cilium policy at decommission. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | coordination.k8s.io / leases | all in scope | create | Create the leader lock; Kubernetes RBAC cannot name-scope CREATE. Namespace-scoped residual authority. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | coordination.k8s.io / leases | hanko-operator.hanko.sh | get, update | Read and renew only the configured client-go LeaseLock; no list/watch/patch/delete. |
| with-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications,hankoiamprofiles,hankoimports,hankokeycloakinstances,hankorealms,hankoroles,hankoserviceaccounts,hankosnapshots,hankothemes | all in scope | create | Create five Fleet content kinds, Observe role imports, and opt-in approved Operation children (instance/import/snapshot); no arbitrary request creation. |
| cilium, connected-with-grants, standard, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications,hankoiamprofiles,hankorealms,hankoroles,hankoserviceaccounts,hankothemes | all in scope | create | Create five Fleet content kinds, Observe role imports, and opt-in approved Operation children (instance/import/snapshot); no arbitrary request creation. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications,hankoiamprofiles,hankorealms,hankoserviceaccounts,hankotenants,hankothemes | all in scope | delete | Delete only five Fleet content kinds during owned rollback and HankoTenant during approved decommission. |
| with-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications/finalizers,hankokeycloakinstances/finalizers,hankooperations/finalizers,hankoorganizations/finalizers,hankorealms/finalizers,hankoresourceservers/finalizers,hankoroles/finalizers,hankoserviceaccounts/finalizers,hankosnapshots/finalizers,hankotenants/finalizers,hankothemes/finalizers,hankoworkloadtrusts/finalizers | all in scope | update | Finalizer updates for lifecycle-owning controllers; regular metadata updates use separately reviewed main-resource grants. |
| cilium, connected-with-grants, standard, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications/finalizers,hankokeycloakinstances/finalizers,hankoorganizations/finalizers,hankorealms/finalizers,hankoresourceservers/finalizers,hankoroles/finalizers,hankoserviceaccounts/finalizers,hankotenants/finalizers,hankothemes/finalizers,hankoworkloadtrusts/finalizers | all in scope | update | Finalizer updates for lifecycle-owning controllers; regular metadata updates use separately reviewed main-resource grants. |
| with-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications/status,hankoiamprofiles/status,hankoimports/status,hankoissuers/status,hankokeycloakinstances/status,hankomeshservices/status,hankooperations/status,hankoorganizations/status,hankorealms/status,hankoresourceservers/status,hankoroles/status,hankoserviceaccounts/status,hankosnapshots/status,hankotenants/status,hankothemes/status,hankoworkloadtrusts/status | all in scope | get, patch, update | Publish observed status independently of spec/metadata write authority. |
| cilium, connected-with-grants, standard, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications/status,hankoiamprofiles/status,hankoimports/status,hankoissuers/status,hankokeycloakinstances/status,hankomeshservices/status,hankoorganizations/status,hankorealms/status,hankoresourceservers/status,hankoroles/status,hankoserviceaccounts/status,hankotenants/status,hankothemes/status,hankoworkloadtrusts/status | all in scope | get, patch, update | Publish observed status independently of spec/metadata write authority. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoemailproviders/status | all in scope | get, patch, update | Publish observed status independently of spec/metadata write authority. |
| with-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications,hankoiamprofiles,hankokeycloakinstances,hankooperations,hankoorganizations,hankorealms,hankoresourceservers,hankoroles,hankoserviceaccounts,hankosnapshots,hankotenants,hankothemes,hankoworkloadtrusts | all in scope | patch, update | Update metadata/finalizers of lifecycle-owned CRs and reviewed Fleet content; Issuer, MeshService, Import and legacy EmailProvider remain status-only writers. |
| cilium, connected-with-grants, standard, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications,hankoiamprofiles,hankokeycloakinstances,hankoorganizations,hankorealms,hankoresourceservers,hankoroles,hankoserviceaccounts,hankotenants,hankothemes,hankoworkloadtrusts | all in scope | patch, update | Update metadata/finalizers of lifecycle-owned CRs and reviewed Fleet content; Issuer, MeshService, Import and legacy EmailProvider remain status-only writers. |
| with-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications,hankoiamprofiles,hankoimports,hankoissuers,hankokeycloakinstances,hankomeshservices,hankooperations,hankoorganizations,hankorealms,hankoresourceservers,hankoroles,hankoserviceaccounts,hankosnapshots,hankotenants,hankothemes,hankoworkloadtrusts | all in scope | get, list, watch | Watch/cache every registered CR; no spec mutation follows from these read grants. |
| cilium, connected-with-grants, standard, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications,hankoiamprofiles,hankoimports,hankoissuers,hankokeycloakinstances,hankomeshservices,hankoorganizations,hankorealms,hankoresourceservers,hankoroles,hankoserviceaccounts,hankotenants,hankothemes,hankoworkloadtrusts | all in scope | get, list, watch | Watch/cache every registered CR; no spec mutation follows from these read grants. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoemailproviders | all in scope | get, list, watch | Watch/cache every registered CR; no spec mutation follows from these read grants. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | monitoring.coreos.com / servicemonitors | security-review-hanko-operator | delete, get | Read/delete the exact optional release metrics monitor at decommission. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | networking.k8s.io / networkpolicies | security-review-hanko-operator, security-review-hanko-operator-theme-jobs | delete | Reconcile managed provider network boundaries; delete exact release policies during decommission. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | networking.k8s.io / networkpolicies | all in scope | create, get, list, patch, update, watch | Reconcile managed provider network boundaries; delete exact release policies during decommission. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | policy / poddisruptionbudgets | all in scope | create, delete, get, list, patch, update, watch | Maintain managed replica availability; remove the owned budget after scale-down. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | Role security-review-hanko-operator / auth | rbac.authorization.k8s.io / rolebindings,roles | security-review-hanko-operator | get, patch | Adopt ownerReferences or remove exact release bindings; mandatory admission forbids changing subjects/roleRef or other delegation metadata. Adopt ownerReferences or remove exact release RBAC at decommission. Mandatory admission preserves rules, subjects, aggregation labels/rules, annotations and finalizers; native escalation prevention remains active. |
| connected-with-grants | Role security-review-hanko-operator-transport-decommission / transport | rbac.authorization.k8s.io / rolebindings,roles | security-review-hanko-operator-mesh-policy | delete, get | Adopt ownerReferences or remove exact release bindings; mandatory admission forbids changing subjects/roleRef or other delegation metadata. Adopt ownerReferences or remove exact release RBAC at decommission. Mandatory admission preserves rules, subjects, aggregation labels/rules, annotations and finalizers; native escalation prevention remains active. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | ClusterRole security-review-hanko-operator-cluster-identity-reader / cluster | rbac.authorization.k8s.io / clusterrolebindings,clusterroles | security-review-hanko-operator-cluster-identity-reader, security-review-hanko-operator-node-reader | delete, get, patch | Adopt ownerReferences/remove exact cluster-reader bindings; admission preserves subjects/roleRef. Adopt ownerReferences/remove exact cluster-reader RBAC through the release anchor; admission forbids rules/aggregation changes and aggregation labels. |
| cilium, connected-with-grants, standard, with-lifecycle, with-sensitive-targets, without-lifecycle | ClusterRole security-review-hanko-operator-cluster-identity-reader / cluster |  / /.well-known/openid-configuration,/openid/v1/jwks | all in scope | get | Read current-cluster public issuer and signing keys; no token issuance or review. |

## Guard workflow

`make preflight` runs `python3 scripts/security-surface.py check`. Any schema,
field-bound, grant or binding drift requires an explicit review. The error names
schema field paths and/or the affected RBAC profile. Wildcards, runtime token
minting/review/exec, impersonation/escalation/bind verbs, misleading named CREATE
rules and leader-lock privilege expansion fail before a snapshot can be made.
The absence of these permissions does not prove every remaining grant safe.

To review an intended change, run
`python3 scripts/security-surface.py snapshot --output /tmp/security-surface.json`,
compare it with the committed inventory, assess existing stored objects and
record the migration/authority rationale. Update the committed inventory only
as an explicit reviewed source change, with CRD/admission and relevant installed
tests. The command never updates the baseline implicitly or changes cluster RBAC.
The final audit/installed acceptance is recorded in the
[security workstream](qualification/security/README.md); see also the
[development execution map](development-backlog.md).

## Observed delegation status (2026-10-17)

The optional explanation origin adds four bounded identity kind/reference strings
and the finite `delegated` relationship. Bounds reuse the existing typed depth/TTL
contract. This raises the inventoried string/collection count from 962 to 966;
348 remain without an explicit maximum. Chart RBAC and served/storage versions
are unchanged. The frozen unpublished ResourceServer schema and Go development
contract are updated in this batch; regenerate clients/CRDs before enabling it.
The extension/profile remains experimental and is not stable-contract acceptance.


## Experimental beta envelope (2026-10-19)

Three served beta schemas mirror Application, Role and ResourceServer alpha
exactly. At introduction, the previous 17 schema records and four RBAC profiles were unchanged;
new totals count the same 377 fields/collections and 92 unbounded entries again
under beta. This is an expanded served-version inventory, not additional fields
or accepted risk. The migration utility runs with administrator credentials;
the operator receives no CRD, native migration or Secret authority from it.


## IAM budget and CR authority follow-up

Client IDs, role/group names and broker aliases are bounded to 255 characters;
new nonempty identifiers reject C0/DEL control characters while retaining Unicode
and provider-native punctuation. Descriptions use a 1,024-character development
budget; URLs use 2,048. Role/scope/domain/client-role and redirect lists have at
most 64 entries; credential projections have at most 32. Item lengths are bounded
independently. These are explicit development API budgets, not a guarantee that
every provider accepts every admitted value. Existing provider/runtime checks
remain required, including SAML and redirect semantics.

Inspect saved manifests before updating CRDs: oversized collections, empty client
IDs and control-character identifiers will be refused on subsequent writes.
Correct them through normal reviewed configuration changes; the operator does
not truncate names, rewrite objects or reacquire ownership. Dry-run manifests
against the candidate API first. The unpublished alpha/beta conversion decision
is explicitly refreshed to the same schema in both versions; default storage
and stable classification are unchanged. `checkIAMInputBudgets` exercises valid
maxima, over-budget values and unsafe identifiers on real API servers.

The operator now reads every registered kind but creates only Fleet content,
Observe role imports and opt-in lifecycle children. It deletes only the five
Fleet content kinds and HankoTenant at decommission. Issuer, MeshService, Import
and legacy EmailProvider metadata/spec are read-only to this principal; status
publication remains separate. `checkCustomResourceRBAC` checks the live
authorizer with lifecycle off/on, plus actual denied Issuer/MeshService writes
and allowed status patches. The inventory rejects attempts to restore the bulk
writer before a new snapshot can be made. Dynamic named CREATE remains
namespace-scoped; controller ownership checks and remaining broad Secret and
Deployment grants still need their independent review in #99.

The [incident collector](operations-runbooks.md#incident-evidence-without-secrets)
adds a separately tested offline export path for #103. It does not implement the
outstanding independently approved finalizer-release workflow.

The initial unpublished `public-0.1.0` candidate schema snapshots for Application
and Role are refreshed explicitly with these admission bounds. Their compiler
intent/plan identities and corpus objects are unchanged; this does not replace
a published baseline or grant stable compatibility.

An existing object with an invalid native identity needs a separately reviewed
object/provider migration. Do not rename a provider object, drop its CRD or
remove its finalizer just to satisfy these admission bounds. Metadata writes
on an invalid stored object may also be refused; assess these objects before
applying the candidate CRDs.

## Public input budget completion

This follow-up closes 103 additional served-schema input gaps, including shared
beta fields. Mapper names use 63 characters, provider aliases/claims use 255,
match values and client/role attribute values use 4,096, and fixed token-claim
or broker-configuration values use 16,384. Existing Unicode/punctuation remains
available where supported. Lifecycle image references and Hub URLs use 2,048;
Kubernetes references use their explicit name/namespace budgets. Theme pull
Secrets and imported resource claims have at most 32 entries. Resource maps
have at most 32 keys and quantity strings at most 64 characters.

Ordinary fields use Go validation markers. The reviewed
[imported-field policy](../api/schema-input-bounds.json) adds constraints that
controller-gen cannot attach to external Kubernetes fields or map values.
`make manifests` applies it explicitly, preserves existing empty reference
defaults, and refuses missing paths, changed types or conflicting limits.
It never changes storage or conversion strategy. The frozen unpublished IAM
schemas and conversion hashes are refreshed together; Go field types and the
compiler corpus intent identities are unchanged.

`checkPublicInputBudgets` uses 95 independent fixtures with accepted maxima and
rejected oversized values, including Unicode map values, nested role values,
quantity unions, date-time fields and alpha/beta parity. Native map-key tests
cover empty, 255- and 256-character keys. These are API admission checks, not
proof that a provider will accept or converge every admitted value.

Before upgrading these development CRDs, inspect saved manifests for oversized
values and maps and use `kubectl apply --dry-run=server -f MANIFEST` against the
candidate API. Correct configuration through the ordinary reviewed procedure;
do not truncate identities, remove finalizers or recreate provider objects to
make a manifest pass. Status budgets are described below. The final instrumented audit and exact-candidate installed evidence are tracked
in the [security qualification record](qualification/security/README.md).

## Status budgets and recovery inventories

The [status policy](../api/schema-status-bounds.json) closes the remaining 294
served-schema inventory gaps using 232 reviewed paths, shared unchanged by
alpha and beta. Fixed SHA-256 fields gain an explicit 71-character maximum;
their existing patterns already imposed that format. Imported timestamps use
64 characters. New condition-list bounds are 32 entries; existing stricter
limits and type-keyed SSA ownership are retained. Provider IDs and UIDs use
128 characters, discovery URLs 4,096, group paths 16,384, resource references
their Kubernetes budgets, and lifecycle diagnostics 4,096. These limits do not
turn copied status into ownership, approval or execution authority.

Application identity/claim mapper inventories, Secret projection inventories,
and realm broker/mapper inventories retain up to 128 entries. Before a native
write batch, the controller reserves space for both the complete previous
inventory and every desired entry. It refuses a batch that cannot preserve
that worst-case checkpoint; it never clips identities or silently discards
cleanup references. This reservation is deliberately conservative even when
some desired entries may resolve to existing IDs. A zero-entry desired batch
can still run its ordinary owned cleanup at the capacity limit. Resolve
failed cleanup and review the desired batch size before introducing further
identities; this guard does not authorize automatic pruning or deletion.

A partial broker update retains every previous child mapper ID until the
existing cleanup procedure acknowledges its removal. The mapper list now uses
the compound `(name, keycloakID)` SSA key: an interrupted replacement can retain
old and new IDs with the same name, while duplicate pairs are refused. Review
existing field-manager ownership before applying this development CRD change.
Oversized operation messages become a fixed public diagnostic without altering
the step result, accepted child UID or timestamps. Identifiers and checkpoint
hashes are never truncated.

The independent status corpus tests accepted maxima and rejected oversized
values at every newly constrained path on each served version, including the
precise invalid field. Real API storage also exercises adoption from the previous
mapper list schema with existing SSA ownership, same-name replacement IDs and
duplicate-pair refusal, without forcing another writer's fields. Before applying these candidate CRDs, inspect
existing status as well as spec for over-budget values. A spec-only dry run
does not validate the stored status subresource. Do not erase recovery
inventories or finalizers to pass validation; retain backups and complete the
ordinary reviewed recovery procedure first. The inventory is a development
record; the [security audit record](qualification/security/README.md) carries
the final review and exact-candidate qualification decision.

## Every public field has an admission fixture

The [frozen corpus](../api/testdata/public-field-budgets.json) has 968 alpha
field paths, covering all 1,347 served paths through identical alpha/beta
versions. A live-schema walk rejects missing/removed fixture paths and never
supplies their expected bounds. Each fixture submits a valid representative and
isolated oversized, empty, pattern-breaking or unsupported-enum values where
applicable. A refusal must identify that exact field. Size refusals must carry
Kubernetes' typed `FieldValueTooLong`/`FieldValueTooMany` causes, so a different
pattern/enum error cannot conceal a missing size check. The existing independent
95 input and 232 status budget cases additionally exercise accepted maxima.
These checks prove API enforcement, not provider acceptance of every allowed
configuration. Real provider convergence remains in the native/installed suites.

The explicit CORS entry set adds two paths in each Application version, bounded
to 64 entries of 255 characters. Upgrades retain the previous `+` default when
the field is omitted; existing installations can review and declare their native
entries before ownership migration. The security inventory review retains every
previous field bound and the exact RBAC profiles. Credentials, URL parameters
and wildcard authorities remain outside this field's allowed values.

## Native Keycloak storage ceilings

Eight paths use 255 characters: OIDC redirects and SAML ACS destinations;
Application/Realm role descriptions; HankoRole description and native attribute
values; authorization scope descriptions and resource URI items. This follows
the pinned [official migration definitions and source identities](qualification/security/2026-10-19/bounded-contract/native-storage-limits.json),
unchanged between Keycloak 26.7.5 and 26.8.0. Scope description maps to the native
scope display name. Resource URI items are nonempty and reject C0/DEL while
retaining relative paths, Unicode and wildcards. Kubernetes admission, typed
compiler refusals before provider I/O, and real HTTPS native maximum/read-back
tests cover the mapping. SAML ACS rejects oversize input before URL parsing and
has its own fuzz target. Decoded C0/DEL, invalid UTF-8 and escaped wildcards/backslashes are refused while encoded spaces and valid Unicode remain available.

The native client/realm attributes and protocol/IdP mapper values use NCLOB/CLOB
storage; their existing 2,048/4,096/16,384 budgets are retained. Native tests
separately read back long logout metadata, attributes and fixed claims. These
storage facts do not certify every database, URL meaning or configuration.

Migration: review saved manifests and stored objects against the eight tighter
limits before upgrading these development CRDs. The previous API could accept
configuration larger than the qualified provider columns. Correct desired
configuration through its responsible writer; do not truncate identities or
remove finalizers/checkpoints. Existing legal values, canonical plan identities,
Go signatures and alpha/beta parity are preserved. The three unpublished schema
snapshots and conversion hashes are explicitly refreshed; no published baseline,
storage default, conversion strategy or stable classification changes.
