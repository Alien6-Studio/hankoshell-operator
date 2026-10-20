# Audited finalizer release

The administrator boundary is recorded in [ADR-051](architecture/decisions/ADR-051-audited-finalizer-release.md).

Use normal reconciliation first. This exceptional administrator command releases
one selected finalizer from an already terminating Hanko object. Two distinct
authenticated administrators must accept **orphaned provider state and Kubernetes
garbage collection**. The command does not inspect or clean Keycloak, workloads,
credentials, delegation grants or external dependencies. Kubernetes may delete
owned children after the finalizer is removed. Review these effects before approval.

Supported kinds are Application, Realm, Role, Organization, ServiceAccount,
WorkloadTrust, Theme and ResourceServer. The exact ten finalizer strings are
allowlisted in `tools/operations/finalizer_recovery.py`; an annotation with a similar name
is not a finalizer. Each plan selects one string and preserves every other entry.
Instance, Tenant, Operation and Snapshot have no release profile in this tool.

## Install administrator authority

Use the reviewed repository checkout and Python dependencies from
`tools/requirements.txt`. A cluster administrator installs the following
manifests independently of Helm. The operator receives no recovery permissions.
Map two human identities through your identity provider to the exact groups
`hanko:recovery-executors` and `hanko:recovery-approvers`. Service accounts and
other `system:` identities are refused, including identities in both groups.
The requester and approver must have distinct authenticated usernames, even
when their group memberships overlap. Identity enrollment itself is environment
specific and **UNQUALIFIED** by the local fixture.

```sh
kubectl --context "$administrator_context" apply -f config/recovery/approval-policy.yaml
kubectl --context "$administrator_context" apply -f config/recovery/audit-access.yaml
kubectl --context "$administrator_context" -n "$target_namespace" apply -f config/recovery/target-access.yaml
```

The dedicated `hanko-recovery-audit` namespace accepts only fixed-shape immutable
records. Admission binds each record to its authenticated creator, restricts
approval to a distinct approver, refuses ownership references/binary data, and
denies updates and deletes. The CLI checks the installed policy and binding
against the reviewed manifest, binds their UIDs into the plan and requires a
dry-run denial proving the binding is active. Missing or changed guards fail closed.

Executor RBAC grants patch on the eight selected CR kinds in the target namespace;
approvers have read access only. These are privileged administrator roles:
Kubernetes RBAC cannot restrict a patch to one field, and admission protects the
audit records, not every manual CR patch. This workflow does not prevent a
privileged administrator bypassing the CLI, changing the guard or deleting the
audit namespace. Restrict that authority and retain external API audit logs under
your own retention policy. ConfigMap records are not an independently durable or
tamper-proof archive. Export them privately; never treat them as public incident evidence.

## Request, review and execute

Schedule a maintenance window. Freeze Helm/GitOps/other operator writers and scale
**every** operator Deployment in the cluster to zero using its actual namespace
and name. Wait for their Pods to disappear. For each deployment, the exact actions
are:

```sh
kubectl --context "$administrator_context" -n "$operator_namespace" scale deployment "$operator_deployment" --replicas=0
kubectl --context "$administrator_context" -n "$operator_namespace" wait --for=delete pod -l app.kubernetes.io/name=hankoshell-operator --timeout=120s
```

The CLI requires a nonempty, unpaginated inventory of operator Deployments at
zero replicas and no operator Pods across the cluster, using the chart's name
label. It rechecks immediately before the target patch. This is a maintenance
check, not an atomic lock against another administrator rescaling or relabeling
an operator. Keep the deployment freeze in force throughout the procedure.
Actual node/process shutdown and GitOps coordination are **UNQUALIFIED** by an
API-only fixture; the running-replica refusal is tested separately.

For a terminating role, the requester runs:

```sh
umask 077
python3 -m tools.operations.finalizer_release --context "$executor_context" plan \
  --kind HankoRole --namespace "$target_namespace" --name "$target_name" \
  --finalizer hanko.sh/role-cleanup --output "$private_plan"
python3 -m tools.operations.finalizer_release --context "$executor_context" request --plan "$private_plan"
```

The plan file is exclusively created with mode 0600. It contains private object
names, UIDs, resourceVersion, deletion timestamp, generation, a digest of the
complete finalizer list, cluster/namespace/guard UIDs, requester identity and a
fresh nonce. It contains no spec, status, annotations, credentials or foreign
finalizer names. The default lifetime is 15 minutes; `--ttl` accepts 60–3600
seconds. Expiration uses the administrator workstation clock; synchronize clocks.
Transfer this private file through an approved channel to the independent
approver, who reviews the target and external effects before executing:

```sh
python3 -m tools.operations.finalizer_release --context "$approver_context" approve --plan "$private_plan" \
  --accept-orphaned-provider-state-and-garbage-collection
```

The original requester then executes:

```sh
python3 -m tools.operations.finalizer_release --context "$executor_context" execute --plan "$private_plan" \
  --accept-orphaned-provider-state-and-garbage-collection
```

Request and approval ConfigMap UIDs are bound into an immutable intent record,
which must be acknowledged and read back before the target mutation. A JSON
Patch tests UID, resourceVersion, deletion timestamp and the complete finalizer
list, then removes just the selected array entry. Any concurrent change refuses
the release. An object replacement, namespace replacement, policy replacement,
expired plan, missing approval or unavailable recorder also refuses it.
Approval applies to this one plan until expiry; there is no standing permission
or automatic renewal. To cancel, the requester stops the procedure and lets it
expire. Group revocation does not retrospectively revoke an already recorded
approval. Suspend executor patch authority if immediate revocation is required.

## Interrupted or uncertain execution

An API write can succeed while its acknowledgement is lost. The CLI never
automatically retries a write. After an intent exists, `execute` refuses another
target patch; use the original plan for a read-only target observation:

```sh
python3 -m tools.operations.finalizer_release --context "$executor_context" observe --plan "$private_plan"
```

Observation can run after expiration. It writes an immutable receipt saying
`TargetAbsent`, `TargetReplaced`, `SelectedFinalizerAbsent` or
`SelectedFinalizerPresent`, bound to the original intent. It never claims provider
cleanup or proves who changed the object. An existing receipt is retained as its
original observation. The command output contains only phase and plan digest;
inspect the private receipt to distinguish outcomes.

If the intent was recorded but no patch occurred, observation can report the
finalizer still present. Investigate first, then prepare a **new plan and independent
approval** if another attempt is justified. Do not delete the old intent or reuse
its approval. If a record-create acknowledgement was lost, rerunning `request`
or `approve` reads back the exact immutable record; it never replaces it. Missing
or altered records require administrator investigation. After the incident,
reconcile orphaned native state separately and restore the reviewed replica
count and GitOps control; this tool does not choose that count or restart workloads.

## Executable qualification

`tests/tooling/test_finalizer_recovery.py` injects stale UIDs/versions/generations,
changed finalizers, expired approvals, active operators, changed guards, failed
audit writes, CAS races and lost acknowledgements. It verifies no target replay,
foreign-finalizer preservation, bounded parsing and private exclusive files.

`api/v1alpha1/finalizer_recovery_integration_test.go` installs the exact three
manifests, authenticates distinct executor/approver identities, checks admission
denials for forged actors/self-approval/service accounts/mutable or extra data,
and denies audit rewriting/deletion. It invokes
`tools/qualification/fixtures/finalizer_recovery_fixture.py` against a real disposable API server,
using the actual CLI and kubectl transport on the mandatory Kubernetes matrix:

```sh
make integration-test KUBERNETES_VERSION=1.35.0
make integration-test KUBERNETES_VERSION=1.36.2
make integration-test KUBERNETES_VERSION=1.37.0
```

The fixture releases a terminating Role while preserving a foreign finalizer;
it does not run provider cleanup, node garbage collection, an external audit
recorder, a public release upgrade or a connected production recovery scenario.
Those limits remain **UNQUALIFIED** in the operational contract.

Executable source: [tools/operations/finalizer_release.py](../tools/operations/finalizer_release.py).
