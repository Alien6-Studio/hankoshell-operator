# Experimental API storage migration

Application, Role and ResourceServer serve v1alpha1 and v1beta1 with identical
schemas. Alpha remains the controller hub and installation default. Migration
changes Kubernetes encoding only; it does not call Keycloak, rotate credentials,
change ownership or graduate an API. Public cross-release compatibility remains
unqualified. See the [conversion decision](api-conversion.json).

## Prerequisites

Use the exact reviewed source, Python 3.12+, `pip install -r tools/requirements.txt`
and kubectl with an administrator context for the target cluster. The command
accepts the exact Kubernetes pins in versions.json. The native
[StorageVersionMigration API](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/storage-version-migration/)
must be available and its controller running. Kubernetes 1.35/1.36 require the
StorageVersionMigrator feature gate and storagemigration.k8s.io/v1beta1 API;
1.37 provides the v1 API by default. Missing native support refuses the plan
before storage changes. A managed service may restrict those control-plane settings.

Administrators need read access to cluster discovery, kube-system Namespace,
operator Deployments/Pods and all three resource kinds; get/update on the three
CRDs and their status; get/list/create on native StorageVersionMigrations; and
get/create/update ConfigMaps in the dedicated journal namespace. No Secret,
provider, Pod exec, deletion or token authority is used by the migration command.
The native fixture separately uses exec only in its disposable etcd Pod.

Retain a verified recovery backup through your existing private process. Suspend
GitOps, autoscalers and every competing writer, then stop all operator deployments
(including managed provider reconciliation). The command requires their standard
`app.kubernetes.io/name=hanko-operator` or `hankoshell-operator` label, or the
chart's fixed `app=hanko-operator` Pod/template label for custom names. All must
have zero replicas and no remaining Pods, including terminating ones. It scans
paginated workload inventories, checks this repeatedly and does not stop them
for you. Verify that no controller with a different label manages these objects.

Every selected CR must be Ready, InSync, completely observed and applied at its
current generation, with any adoption receipt verified and no pending deletion.
Observe/imported objects instead require a current observation with no applied
generation; migration preserves their read-only mode and import latch.
Configurations with application secretRotationPolicy or resource-server
delegation are deliberately refused: CR status alone cannot certify their native
transaction is idle. Preserve those policies/journals and use their dedicated
inspection procedure; this utility currently offers no override for them.

## Plan, approve and run

After installing the two-version CRDs with the preflight below, stop writers and
prepare a dedicated journal namespace:

```sh
kubectl create namespace hanko-migrations
python3 -m tools.operations.storage_migration plan --target v1beta1 \
  --namespace hanko-migrations --plan /private/path/to-beta.json
```

The read-only plan prints its canonical SHA256 and exact object count. The file
is created exclusively with mode 0600; it binds cluster UID, CRD UIDs, current
storage, target version and every object UID/name/namespace/generation/resourceVersion.
Review that inventory and retain the printed hash as `$approved_plan_sha256`.
No spec, status, credential, provider ID or payload hash is persisted in it.

```sh
python3 -m tools.operations.storage_migration run --plan /private/path/to-beta.json \
  --approve "$approved_plan_sha256" --timeout 1800
python3 -m tools.operations.storage_migration status --plan /private/path/to-beta.json \
  --approve "$approved_plan_sha256"
```

All commands accept `--kubectl`, `--kubeconfig` and `--context`. The utility uses a
short-lived loopback kubectl proxy with restricted paths; it does not copy tokens
from kubeconfig. It revalidates the entire inventory before the first write,
changes one CRD storage flag at a time, waits for discovery to confirm the new
encoder, then creates a fresh native StorageVersionMigration. Only native success
at the current CRD generation and an unchanged semantic snapshot permit reducing
storedVersions to the target. UID, generation, spec/status, approvals, opaque
journals, finalizers and managedFields must survive; only root apiVersion and
resourceVersion may differ. Failed or unknown writes never clear old storedVersions.

CRD spec/status updates use resourceVersion compare-and-swap. Only an explicit
HTTP 409 permits another attempt, bounded to four attempts per update. Each
attempt rechecks CRD identity, schema/generation, storage selection, quiescent
writers and unchanged object meaning; a stored-version commit additionally
requires fresh native success. Unknown write outcomes are not retried. A resumed
or completed execution skips unchanged CRD writes but still obtains new native
migration proof. These retries do not relax plan approval or migration deadlines.

The ConfigMap journal records progress, not authority or physical migration proof.
`status` is informational, including when it says Committed. Every `run`, including
a repeated completed run, requires three fresh native migrations. This costs native
jobs but prevents forged/stale completion from skipping storage verification.
Native migration objects and journals remain for administrator audit.

## Interruption and rollback

After a timeout, lost acknowledgement or process restart, keep writers stopped.
Rerun the same approved plan. Pending native jobs are awaited; existing jobs are
not replaced or deleted. Resume accepts resourceVersion changes from earlier
rewrites but requires the exact approved UID set and generation, and checks every object's idle
state again. Replaced/deleted/new objects or changed ownership require review,
not journal deletion. Do not manually clear storedVersions to bypass a refusal.
The journal UID and optimistic resourceVersion guard concurrent administrators;
coordinate a single migration runner. An interrupted native rewrite and an
interrupted storedVersions commit use the same resume command; do not infer
which CRD completed from the process exit alone:

```sh
python3 -m tools.operations.storage_migration status --plan /private/path/to-beta.json \
  --approve "$approved_plan_sha256"
python3 -m tools.operations.storage_migration run --plan /private/path/to-beta.json \
  --approve "$approved_plan_sha256" --timeout 1800
```

The installed fixture stops actual CLI processes after `Rewriting` and after
the first `Committed` resource checkpoint, in both migration directions. It
requires either the original storage version or verified native success and
target-encoded bytes, then restarts with the same reviewed plan and compares the
complete object meaning. Kubernetes can already finish and update storedVersions
while the administrator process is stopped; see the
[native migration contract](https://kubernetes.io/blog/2026/08/31/kubernetes-v1-37-storage-version-migration-ga/).
Its test-only pause wrapper is not a production migration option.

Rollback is a new plan with `--target v1alpha1`, a new review/hash, and the same
native proof. It does not remove served beta or downgrade a chart/controller.
Verify both served readers, storedVersions and workloads before restoring writers
and the original operator replica counts. Rotation/delegation refusals apply in
both directions.

## CRD upgrades and chart rollback

Helm does not upgrade files in crds/. Never apply bundled CRDs blindly over an
installation already storing beta; their installation defaults still use alpha.
The read-only preflight rejects orphaned stored versions, removing a served
reader, incompatible schemas/subresources/selectors, and identity/conversion
changes. Rendering preserves the live storage flag and never emits server status:

```sh
python3 -m tools.operations.storage_migration check-crds --crds "$reviewed_chart/crds"
python3 -m tools.operations.storage_migration render-crds --crds "$reviewed_chart/crds" \
  > /private/path/reviewed-crds.yaml
# Inspect the rendered file, then apply through your normal CRD ownership process.
kubectl apply --server-side -f /private/path/reviewed-crds.yaml
```

Schema/topology changes require their own reviewed migration; this preflight
does not silently approve them. Coordinate the check/render/apply interval with
all other administrators. The chart also uses live lookup to refuse versions
still present in storedVersions but absent from its bundled reader envelope.
Offline `helm template` cannot perform this live check, and historical charts
do not acquire the new guard: always run the explicit preflight before rollback.

## Local qualification

```sh
python3 -m unittest discover -s tests/tooling -t . -p 'test_*migration*.py'
python3 -m tools.qualification.scenarios.storage_migration_installed_test \
  --kind /path/to/kind --kubectl /path/to/kubectl \
  --helm /path/to/helm \
  --kubernetes-version 1.37.0 --output /private/path/fresh-migration-test
```

The installed fixture creates and removes its own cluster using the pinned kind
image. It enables the native feature/API on 1.35/1.36, uses synthetic objects and
a zero-replica operator, then runs alpha → beta → alpha, four process
interruptions and repeated approved runs.
It checks actual etcd bytes, native success, UID/spec/status/managedFields and
upgrade rendering. Its report counts sixteen fresh native migrations. This is
development storage evidence, not a provider or public predecessor upgrade test.
The real-API Go fixture separately checks all 20 served schemas and strict unknown
field rejection. Go conversion tests exercise every exported field, lists, deep
copy independence and bounded hostile JSON fuzz input.

CI runs this native fixture on all three reviewed Kubernetes versions. The
protected aggregate requires every cell to succeed, independently of provider
tests. Only its bounded report is uploaded; kubeconfig and reviewed plan files
are excluded. Cleanup failures retain the qualification phase and a fixed failure
category, remove the disposable kubeconfig, and fail the run rather than hiding
its report. The weekly qualification uses the same matrix.

For Kubernetes 1.36.2, additionally pass `--node-archive` with the official Linux
server archive for the Docker architecture. The fixture verifies the reviewed
SHA256 in versions.json before building a temporary node with the pinned base;
it never substitutes a different patch version and removes that temporary image.

Executable qualification fixture: [tools/qualification/scenarios/storage_migration_installed_test.py](../tools/qualification/scenarios/storage_migration_installed_test.py).

The `make qualify PROFILE=storage` entry point was requalified after the tooling
move: [Kubernetes 1.35.0 report](qualification/storage/2026-10-20/tooling-layout-kubernetes-1.35.0.json).
All 16 native migrations passed, including real conflicts and process interruptions
in both directions; the disposable cluster was removed.
