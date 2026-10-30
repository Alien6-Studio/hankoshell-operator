# CRD validation and RBAC review

The [security inventory](../tools/qualification/config/contracts/security-surface.json)
freezes all 17 served `v1alpha1` CRD schemas, field bounds, rendered grants,
bindings and mandatory admission policies across six chart profiles.
`make preflight` rejects drift and unbounded strings, lists or typed maps.
Finite string enums count as bounded. This inventory supports review; it does
not replace provider qualification or an independent security audit.

## Embedded verifier package evidence

The final image carries `usr/share/hankoshell-operator/verifier-evidence.json`.
The Cosign build generates it from the package graph for the target architecture
and the exact compiled binary. Final-image qualification verifies the binary
SHA-256, toolchain, architecture, Cosign version and reviewed dependency pins,
and rejects missing evidence or any deprecated `golang.org/x/crypto/openpgp`
package. The native installer emits the same evidence beside its executable.

`GO-2026-5932` concerns the abandoned OpenPGP packages within `x/crypto`.
Other packages from that module remain legitimate dependencies.
Artifact Hub uses Trivy, which reads the binary's module metadata. Its
module-level alert can therefore remain after OpenPGP imports have been removed.
Removing an import does not promise that a third-party module-level report will
be empty. Raw reports remain in delivery evidence without suppression; the
package inventory is additional evidence tied to the actual image.

## Admission bounds

Go validation markers and the [imported-field policy](../api/schema-input-bounds.json)
define input limits. The [status policy](../api/schema-status-bounds.json)
constrains status fields that controller-gen cannot annotate directly.
`make manifests` applies these policies and refuses missing paths, changed types
or conflicting limits. The API is served and stored only as `v1alpha1`.

The [public-field corpus](../api/testdata/public-field-budgets.json) exercises
every declared field on real supported Kubernetes APIs. Independent
[input](../api/v1alpha1/input_budgets_integration_test.go) and
[status](../api/v1alpha1/status_budgets_integration_test.go) fixtures test accepted
maxima and rejected over-budget values. Refusals must identify the exact field;
size refusals must carry Kubernetes' typed size errors.

References use Kubernetes name bounds and reject paths, uppercase and malformed
labels. Native identifiers retain Unicode and provider punctuation while refusing
control characters. Attribute/configuration map keys require 1..255 characters;
integer-or-string resource quantities are limited to 64 characters.
Collections and their items have separate limits.

Keycloak's native storage constrains redirects, SAML ACS destinations, role/scope
descriptions, role attributes and resource URI items to 255 characters. Native
HTTPS read-back tests and compiler refusals cover these mappings. Longer
client/realm attributes and mapper values retain their separately declared
budgets. Admission success alone does not prove provider acceptance.

HankoTheme can identify a precompiled JAR with `artifactSHA256`, exactly 64
lowercase hexadecimal characters. This mode refuses build-time appearance inputs
and verifies the copied bytes before replacing the installed file. Image approval,
namespace storage and workload permissions remain required.

## Recovery inventories

Identity/claim mapper, Secret projection and realm broker inventories retain
up to 128 entries. Before a native write batch, the controller reserves space
for the complete previous inventory and every desired entry. It refuses a batch
that cannot preserve its recovery checkpoint and never clips identities or
silently drops cleanup references. An empty desired batch can still clean up
owned state.

Interrupted broker replacement preserves previous child mapper IDs. The compound
`(name, keycloakID)` SSA key allows old and new IDs with the same name while
refusing duplicate pairs. Oversized diagnostic messages become fixed public
messages; identifiers, child UIDs, checkpoints and step results are preserved.

Before changing CRDs, assess saved manifests and stored spec **and status**.
Dry-run manifests against the candidate API; a spec-only dry run does not
validate stored status. Correct desired configuration through its responsible
writer. Do not truncate identities, remove finalizers, discard recovery records
or recreate provider objects to bypass validation. The initial public v1.0.0 had
no earlier public predecessor; later releases must assess the actual published
schemas and stored objects before migration.

## Rendered grants and their review rationale

Secret and Deployment writes require exact administrator targets and mandatory
fail-closed admission. Credential inputs use uncached namespace-local `get`,
without default list/watch. A CR author is not a hostile-tenant isolation boundary;
use separate operator namespaces and credentials where that boundary is required.

The main Role grants `leases/create` and exact-name `leases/get,update` for
`hanko-operator.hanko.sh`. Kubernetes cannot name-scope CREATE. Real API tests
prove lock creation/renewal and deny foreign reads/writes, listing and deletion.

Profiles: `standard`, `without-lifecycle`, `with-lifecycle`, `cilium`,
`connected-with-grants`, and `with-sensitive-targets`. Exact bindings and subjects
are in the inventory. See [write authority configuration](secure-deployment.md#exact-secret-and-deployment-write-authority).

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

## Reviewing a change

Run `make preflight`. To assess an intended change, generate a separate snapshot:

```sh
python3 -m tools.qualification.checks.security_surface snapshot --output /tmp/security-surface.json
```

Compare it with the committed inventory and review existing stored objects,
authority changes and migration needs before updating the baseline. The command
never changes the baseline or cluster RBAC implicitly. Wildcards, token minting,
review/exec, impersonation/escalation/bind, misleading named CREATE rules and
leader-lock privilege expansion are rejected before snapshot creation.

The 1.1.0 task-authorization review adds only the optional `required` enum in
delegation spec and its bounded explanation projection, plus the one-hop rule.
Existing objects omit the field and keep their previous semantics. The separate
public capability GET introduces no administrative role or write permission.
Independent admission cases cover both paths. Before restoring an older schema,
withdraw task grants and follow the [task rollback sequence](rfcs/RFC-0002-task-authorization.md);
an older schema must not silently prune an active task requirement.

[API authorization tests](../api/v1alpha1/custom_rbac_integration_test.go),
[installed qualification](../.github/workflows/ci.yml) and
[finalizer recovery](finalizer-recovery.md) exercise the separate enforcement
boundaries. [Incident collection](operations-runbooks.md#incident-evidence-without-secrets)
exports only allowlisted evidence. The initial release acceptance is recorded in
[#106](https://github.com/Alien6-Studio/hankoshell-operator/issues/106).

## Studio composition migration (2026-10-30)

The Studio compiler adds three optional bounded inputs: `HankoTheme.spec.projectGzip`
(base64 gzip, at most 900,000 characters), `projectSHA256` (64 lowercase hex
characters), and `HankoRealm.spec.emailTheme` (optional theme name). The controller
checks both source fields together, limits decompression to 40 MiB, verifies the
source digest and rejects mixing a project with legacy design tokens or an
artifact installer. The reviewed compiler validates the complete JSON contract;
project data cannot select executable plugins or dependencies.

An immutable source ConfigMap is initially owned by the Theme and transferred to
its verified build Job. Job TTL and Kubernetes garbage collection remove this
input. The existing ConfigMap patch permission is sufficient; this change adds
no delete grant, role, credential or admission-policy change in any of the six
reviewed profiles. Build containers retain read-only project mounts and no
service-account token. Existing image approval/signature checks remain required.

Existing objects omit these fields and retain their prior path. An omitted
`emailTheme` leaves the native setting unmanaged; an explicit empty value clears
it. Email references participate in readiness and deletion protection, like login
references. Before restoring an older operator/schema, stop Studio builds and
restore or detach their assignments, including email. Older schemas must reject
project writes using strict field validation rather than silently dropping the
snapshot. Keep published images and compatibility baselines unchanged; the
updated inventory and Go fixture snapshot describe these source additions only.

See [Studio project builds](theme-studio-projects.md) for rollout and qualification.
