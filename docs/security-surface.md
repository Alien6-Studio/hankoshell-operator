# CRD validation and RBAC review inventory

Development checkpoint for #99, with compatibility/runbook guard work for
#94/#103. The [machine inventory](security-surface.json) records every served
schema hash, declared string/array/typed-map bounds, rendered Role/ClusterRole
rule and binding on four reviewed chart profiles. It is not stable-contract
acceptance or an independent security audit.

The inventory contains **962 declared fields/collections across 17 schemas**.
**348 lack an explicit maximum length/cardinality** (finite string enums count as
bounded). A regex, runtime validator, HTTP byte budget or Kubernetes metadata
limit may impose an independent bound; these gaps are not automatically
vulnerabilities. Opaque provider extensions and inherited Kubernetes schemas
still need contextual review. Status is inventoried along with spec.

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
In particular, dynamic Secret/Deployment names, the bulk CR rule and opt-in
transport bookkeeping need further reduction or admission isolation before #99
can close. Controller ownership/consent checks are not Kubernetes admission
protection. A dedicated transport namespace remains an administrator prerequisite.

Profiles: `standard`, `without-lifecycle`, `cilium`, and
`connected-with-grants` (enterprise, transport teardown, mesh projection/egress
and exact cross-namespace workload readers). No permissions are created outside
these rendered fixtures. Bindings and their subjects are recorded in the JSON.

| Profiles | Role / namespace | API group / resources | Names | Verbs | Purpose / residual limit |
| --- | --- | --- | --- | --- | --- |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | ,events.k8s.io / events | all in scope | create,patch | Record reconciliation Events through both Kubernetes Event APIs; no list/read/delete. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | core / secrets | all in scope | create,patch,update | Dynamic canonical credential creation/rotation and projections; controller owner/UID/consent checks. These are not Kubernetes admission isolation. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | core / configmaps | all in scope | create,get,list,patch,update,watch | Fleet/checkpoint/runtime metadata and mesh projection; cross-namespace writers are named. Namespace-local dynamic names remain broad. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | core / persistentvolumeclaims | all in scope | get,list,watch | Observe explicitly selected managed/theme storage; no volume writes. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | core / pods,serviceaccounts | all in scope | get,list,watch | Observe managed workload readiness and node identity; no Pod writes or exec. Observe workload identities; decommission patches only the release-owned account. No token minting. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | core / serviceaccounts | security-review-hanko-operator | patch | Observe workload identities; decommission patches only the release-owned account. No token minting. |
| cilium, connected-with-grants, standard, without-lifecycle | ClusterRole security-review-hanko-operator-node-reader / cluster | core / nodes | all in scope | get | Read Pod.nodeName-derived node identity; names are discovered dynamically; no list/watch or writes. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | core / secrets | hanko-hub-enroll,hanko-hub-tls | delete | Read referenced credentials without caching, or delete exact release bootstrap/CA Secrets at approved decommission. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | core / secrets | all in scope | get | Read referenced credentials without caching, or delete exact release bootstrap/CA Secrets at approved decommission. |
| cilium, connected-with-grants, standard, without-lifecycle | ClusterRole security-review-hanko-operator-cluster-identity-reader / cluster | core / namespaces | kube-system | get | Read the exact kube-system UID used to bind this physical cluster. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | core / services | security-review-hanko-operator-metrics | delete | Reconcile managed provider Services, observe mesh egress endpoints, remove exact release metrics Service. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | core / services | all in scope | create,get,list,patch,update,watch | Reconcile managed provider Services, observe mesh egress endpoints, remove exact release metrics Service. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | apps / deployments | security-review-hanko-operator | delete | Manage provider infrastructure or approved self-update; release deletion is named. Controller ownership checks are not universal admission isolation. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | apps / deployments | all in scope | create,get,list,patch,update,watch | Manage provider infrastructure or approved self-update; release deletion is named. Controller ownership checks are not universal admission isolation. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | batch / jobs | all in scope | create,delete,get,list,watch | Run and observe approved theme/snapshot Jobs, then clean owned jobs; dynamic names require namespace scope. |
| cilium | Role security-review-hanko-operator / auth | cilium.io / ciliumnetworkpolicies | security-review-hanko-operator | delete,get | Read/delete the exact optional release Cilium policy at decommission. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | coordination.k8s.io / leases | all in scope | create | Create the leader lock; Kubernetes RBAC cannot name-scope CREATE. Namespace-scoped residual authority. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | coordination.k8s.io / leases | hanko-operator.hanko.sh | get,update | Read and renew only the configured client-go LeaseLock; no list/watch/patch/delete. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications,hankoiamprofiles,hankoimports,hankoissuers,hankokeycloakinstances,hankomeshservices,hankoorganizations,hankorealms,hankoresourceservers,hankoroles,hankoserviceaccounts,hankotenants,hankothemes,hankoworkloadtrusts | all in scope | create,delete,get,list,patch,update,watch | CR cache GET/list/watch, fleet/import/child object delivery and cleanup; status/finalizer writes use their subresources. Per-kind verb reduction remains review work. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications/finalizers,hankokeycloakinstances/finalizers,hankoorganizations/finalizers,hankorealms/finalizers,hankoresourceservers/finalizers,hankoroles/finalizers,hankoserviceaccounts/finalizers,hankotenants/finalizers,hankothemes/finalizers,hankoworkloadtrusts/finalizers | all in scope | update | CR cache GET/list/watch, fleet/import/child object delivery and cleanup; status/finalizer writes use their subresources. Per-kind verb reduction remains review work. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoapplications/status,hankoiamprofiles/status,hankoimports/status,hankoissuers/status,hankokeycloakinstances/status,hankomeshservices/status,hankoorganizations/status,hankorealms/status,hankoresourceservers/status,hankoroles/status,hankoserviceaccounts/status,hankotenants/status,hankothemes/status,hankoworkloadtrusts/status | all in scope | get,patch,update | CR cache GET/list/watch, fleet/import/child object delivery and cleanup; status/finalizer writes use their subresources. Per-kind verb reduction remains review work. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoemailproviders | all in scope | get,list,watch | CR cache GET/list/watch, fleet/import/child object delivery and cleanup; status/finalizer writes use their subresources. Per-kind verb reduction remains review work. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | hanko.sh / hankoemailproviders/status | all in scope | get,patch,update | CR cache GET/list/watch, fleet/import/child object delivery and cleanup; status/finalizer writes use their subresources. Per-kind verb reduction remains review work. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | monitoring.coreos.com / servicemonitors | security-review-hanko-operator | delete,get | Read/delete the exact optional release metrics monitor at decommission. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | networking.k8s.io / networkpolicies | security-review-hanko-operator,security-review-hanko-operator-theme-jobs | delete | Reconcile managed provider network boundaries; delete exact release policies during decommission. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | networking.k8s.io / networkpolicies | all in scope | create,get,list,patch,update,watch | Reconcile managed provider network boundaries; delete exact release policies during decommission. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | policy / poddisruptionbudgets | all in scope | create,delete,get,list,patch,update,watch | Maintain managed replica availability; remove the owned budget after scale-down. |
| cilium, connected-with-grants, standard, without-lifecycle | Role security-review-hanko-operator / auth | rbac.authorization.k8s.io / rolebindings,roles | security-review-hanko-operator | get,patch | Adopt or remove exact release RBAC objects at decommission; no general role binding authority. Adopt or remove exact release RBAC objects at decommission; native Kubernetes escalation protection still applies. |
| cilium, connected-with-grants, standard, without-lifecycle | ClusterRole security-review-hanko-operator-cluster-identity-reader / cluster | rbac.authorization.k8s.io / clusterrolebindings,clusterroles | security-review-hanko-operator-cluster-identity-reader,security-review-hanko-operator-node-reader | delete,get,patch | Adopt/remove exact release cluster-reader bindings through the release anchor. Adopt/remove exact release cluster-reader RBAC through the release anchor; no wildcard or escalation verbs. |
| cilium, connected-with-grants, standard, without-lifecycle | ClusterRole security-review-hanko-operator-cluster-identity-reader / cluster | core / /.well-known/openid-configuration,/openid/v1/jwks | all in scope | get | Read current-cluster public issuer and signing keys; no token issuance or review. |
| connected-with-grants | Role security-review-hanko-operator-mesh-policy / transport | core / configmaps | hanko-mesh-policy | get,patch,update | Fleet/checkpoint/runtime metadata and mesh projection; cross-namespace writers are named. Namespace-local dynamic names remain broad. |
| connected-with-grants | Role security-review-hanko-operator-transport-decommission / transport | core / configmaps | hanko-mesh-policy | delete,get | Fleet/checkpoint/runtime metadata and mesh projection; cross-namespace writers are named. Namespace-local dynamic names remain broad. |
| connected-with-grants | Role security-review-hanko-operator-workload-binding / workloads | core / configmaps | worker-identity | get,patch | Fleet/checkpoint/runtime metadata and mesh projection; cross-namespace writers are named. Namespace-local dynamic names remain broad. |
| connected-with-grants | Role security-review-hanko-operator-workload-binding / workloads | core / serviceaccounts | worker | get | Observe workload identities; decommission patches only the release-owned account. No token minting. |
| connected-with-grants | Role security-review-hanko-operator-transport-decommission / transport | core / secrets | all in scope | delete,get,list | Opt-in transport Helm bookkeeping: namespace-wide get/list/delete. Dedicated namespace prerequisite is documented, not admission-enforced. |
| connected-with-grants | Role security-review-hanko-operator-mesh-egress-reader / egress | core / services | all in scope | get | Reconcile managed provider Services, observe mesh egress endpoints, remove exact release metrics Service. |
| connected-with-grants | Role security-review-hanko-operator-transport-decommission / transport | apps / daemonsets | continuum-continuum-vpn | delete,get | Read/delete only the configured transport release DaemonSet after decommission approval. |
| connected-with-grants | Role security-review-hanko-operator-transport-decommission / transport | rbac.authorization.k8s.io / rolebindings,roles | security-review-hanko-operator-mesh-policy | delete,get | Adopt or remove exact release RBAC objects at decommission; no general role binding authority. Adopt or remove exact release RBAC objects at decommission; native Kubernetes escalation protection still applies. |

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
The full public CRD/least-privilege acceptance and stable conversion matrix
remain open; see the [security workstream](qualification/security/README.md) and
[22-issue execution map](development-backlog.md).
