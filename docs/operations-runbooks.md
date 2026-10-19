# Operator operational runbooks

This is an **initial development** runbook for the v1alpha1 API, before the first
public release. No predecessor-to-public upgrade, production HA, production storage migration,
complete installed delegation matrix or connected installation is qualified. Do not infer
those capabilities from a documented command. [Stable graduation](stable-graduation.md)
and [lifecycle authority](architecture/decisions/ADR-050-experimental-lifecycle-authority.md)
retain their exclusions. Nothing here authorizes publication or bypasses approval.

Every procedure below identifies its executable fixture or states **UNQUALIFIED**.
Choose an approved chart/image digest and reviewed namespace-specific values;
never copy test credentials, fixture CAs or synthetic approvals to production.
Commands with `$variables` require administrator-supplied reviewed inputs.

The [CRD/RBAC security inventory](security-surface.md) records current admission
bounds, grant justifications, unresolved authority limits and the reference-field
migration notice. [The development execution map](development-backlog.md) groups
open issues and distinguishes code from external acceptance evidence.

## Install: standalone and connected

Load and leader-loss reproduction uses `scripts/scale-installed-test.py` with
the exact scanned image and a clean immutable checkout. The
[scale and soak procedure](scale-and-soak.md) documents bounded workers, overload
injection, numeric metrics and the 24-hour minimum. Full transaction HA, owned
realm cascade deletion and production sizing remain **UNQUALIFIED**.

Standalone render/install, using the same flags as `System.install` in
`scripts/system-test.py` (real kind, private-CA Keycloak, namespace RBAC, Restricted
pods, immutable scanned OCI):

```sh
helm template "$release" "$chart_path" --namespace "$namespace" \
  --kube-version "$kubernetes_version" --values "$approved_values" > "$rendered_manifest"
helm install "$release" "$chart_path" --namespace "$namespace" \
  --values "$approved_values" --wait --timeout 180s
kubectl -n "$namespace" rollout status deployment/"$deployment" --timeout=180s
```

Values must bind image digest, Keycloak CA/credential Secret references, exact API
egress and watch namespace; see [secure deployment](secure-deployment.md). Review
the rendered RBAC and admission policies before installing. Do not export
`helm get values --all` into an incident report: legacy/custom values can contain
credentials. Metrics remain off unless the [mTLS configuration](operational-observability.md)
is provided. The installed observability fixture tests enabling and disabling them.

### Connected installation

**UNQUALIFIED: live connected installation.** First provision the independently
approved Hub/Continuum transport and existing tenant credential through their
own administrator processes. This runbook covers the operator side. Review
`charts/hankoshell-operator/values.yaml` and
[the enterprise prerequisites](secure-deployment.md): the approved values must
set `profile: enterprise`, immutable `image.digest`, `hub.enabled`, the exact
HTTPS `hub.endpoint`, existing `hub.tenantID` and `hub.tokenSecret`, and the
reviewed `continuum` relay address/hostname and API egress. The referenced
credential Secret must already contain `hub_token`, `tenant_id`, `cluster_id`
and `expires_at`; provision it through your private secret process. Keep consumed
enrollment tokens out of the values retained for an existing tenant.

```sh
umask 077
helm template "$release" "$chart_path" --namespace "$namespace" \
  --kube-version "$kubernetes_version" --values "$approved_connected_values" > "$private_connected_manifest"
helm install "$release" "$chart_path" --namespace "$namespace" \
  --values "$approved_connected_values" --wait --timeout 180s
kubectl -n "$namespace" rollout status deployment/"$deployment" --timeout=180s
kubectl -n "$namespace" get hankotenant "$tenant" \
  -o jsonpath='{.status.phase}{"\n"}{range .status.conditions[*]}{.type}{" "}{.status}{" "}{.reason}{"\n"}{end}'
```

`charts/hankoshell-operator/tests/keycloak-transport.py` exercises enterprise
HTTPS configuration/refusals; `charts/hankoshell-operator/tests/fleet-plan.py`
checks the independently owned local plan-trust reference. These are render
fixtures. The install, rollout and tenant observation commands above have **not
been qualified against a live Hub/Continuum installation**. Qualify them in the
target environment before relying on them. A running Deployment does not prove
tenant enrollment, a verified plan or successful audit delivery.

## Upgrade, rollback and storage

**UNQUALIFIED: supported public upgrade/rollback paths.** There is no published
predecessor. All 17 resources remain experimental; three IAM resources additionally serve
v1beta1, with default storage still v1alpha1. HankoOperation and
HankoSnapshot are outside stable 1.0 graduation. Managed Upgrade and DBSwitch are
not qualified. Do not use those CRs as a substitute for a tested migration.

Before deploying a development controller that uses realm-filtered ownership
reads, apply the reviewed Application/ServiceAccount CRDs first. [Helm upgrades
do not update files in `crds/`](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/). Verify that both live API endpoints accept the
new selectable field before rolling the controller:

```sh
kubectl apply --server-side -f "$chart_path/crds/hanko.sh_hankoapplications.yaml"
kubectl apply --server-side -f "$chart_path/crds/hanko.sh_hankoserviceaccounts.yaml"
kubectl -n "$namespace" get hankoapplications \
  --field-selector="spec.realmRef=$realm" --limit=1 -o name
kubectl -n "$namespace" get hankoserviceaccounts \
  --field-selector="spec.realmRef=$realm" --limit=1 -o name
```

An empty list is valid; an unsupported-selector response blocks the upgrade.
The controller refuses ownership authorization when these live lists fail.
This prepares the current development API; it does not qualify a public upgrade.

For development chart configuration changes only,
`scripts/observability-installed-test.py` exercises a real Helm upgrade and
rollback to previous reviewed values:

```sh
helm upgrade "$release" "$chart_path" --namespace "$namespace" \
  --values "$approved_values" --wait --timeout 180s
kubectl -n "$namespace" rollout status deployment/"$deployment" --timeout=180s
helm upgrade "$release" "$previous_chart_path" --namespace "$namespace" \
  --values "$previous_approved_values" --wait --timeout 180s
```

This tests same-source configuration rollback, not an application/data rollback.
Before any other upgrade retain the actual previous chart, image, approved values,
CRDs, storedVersions and a provider backup through its separately approved process.
Old metrics configurations used plaintext HTTP; never roll back transport protection
without first disabling metrics or restoring equivalent independently enforced trust.

The API-server fixture `api/v1alpha1/kubernetes_compatibility_test.go` checks
every served version, including opposite-version typed reads/writes for the three
beta resources. [The storage runbook](storage-migration.md) provides explicit
native migration, resume, rollback and CRD upgrade preflight. Migration is never
a chart side effect. Never clear storedVersions manually or overwrite a migrated
CRD with an unreviewed older bundle. Public cross-release paths remain unqualified.

## Leader failover and provider outage

The [installed transaction failover fixture](transaction-failover.md) reproduces
six selected accepted-write boundaries with actual lease-holder replacement.
Its final report and cleanup are required before treating a scenario as qualified.

Process liveness, serving readiness and leader reconciliation readiness are
specified in [observability](operational-observability.md#health-readiness-and-leader-semantics).
`scripts/observability-installed-test.py` starts two replicas, proves exactly one lease
holder, verifies standby probe semantics, removes that leader and observes a new
holder with the same native managed client and credential. This is a bounded
single-node smoke test. The separate
[transaction packet](qualification/transactions/2026-10-19/runtime-dcee6b6/README.md)
retains six real Kubernetes/Keycloak cells, including the caller-scoped live-leader
API partition. The [realm recovery fixture](recovery-and-realm-deletion.md)
tests a five-minute operator API outage and interrupted owned-realm deletion.
These exact-runtime reports do not qualify arbitrary partitions, split brain,
clock skew, every transaction or a 24-hour soak (#96/#95).

Fixture commands (the labels identify this Helm release):

```sh
kubectl -n "$namespace" get lease hanko-operator.hanko.sh \
  -o jsonpath='{.spec.holderIdentity}{"\n"}'
kubectl -n "$namespace" get pods -l "app.kubernetes.io/instance=$release"
kubectl -n "$namespace" delete pod "$confirmed_leader_pod" --wait=true --timeout=60s
kubectl -n "$namespace" rollout status deployment/"$deployment" --timeout=180s
```

Delete only the confirmed leader after reviewing active operations; this command
is a test action, not automatic incident remediation. During a provider outage,
keep liveness independent, retain fail-closed states and avoid restarting all
replicas. `System.reject_wrong_ca` in the installed system fixture tests provider
readiness/write refusal for bad CA, then trust repair and normal reconciliation.
Repair the authoritative CA/endpoint/credential through the existing administrator
process, restart the Deployment only when startup-loaded Keycloak trust changed,
and wait for current observedGeneration and native read-back. Never set TLS
verification off or copy provider error bodies into a ticket.

### IAM provider refusal reasons

Application, Role and ResourceServer reconciliation classify typed provider failures without
copying native paths, error bodies or credentials. Read current condition reasons
with the incident jsonpath command below. The regression
`TestIAMFailureReasonsUseTypedCausesAndPreserveFailureEvidence` checks wrapped
HTTP errors, spoofed strings, prior applied evidence and private-message omission.
These unit-tested decisions are not an installed outage qualification.

| Reason | Administrator action |
| --- | --- |
| `ProviderAuthenticationFailed` | Repair the configured credential through its existing ownership process; preserve pending rotation state. |
| `ProviderPermissionDenied` | Restore the reviewed permission profile; do not switch to a broad administrator credential to force success. |
| `ProviderThrottled`, `ProviderUnavailable` | Restore service/capacity and allow bounded retries; retain journals and approvals. |
| `ProviderObjectNotFound`, `ProviderConflict` | Check native identity and ownership with the separately authorized administrator; never recreate or relabel foreign data to satisfy status. |
| `ProviderRequestRejected` | Review the desired configuration and supported provider capability before changing it. |
| `ReconcileDeadlineExceeded`, `ReconcileCancelled` | Check API/provider reachability and controller shutdown; an unknown write outcome still requires read-back. |
| `StalePlan` | Let fresh reference and authority reads compile a new plan; never reuse stale approval. |
| `ObservationIncomplete`, `DriftDetected` | Restore complete read-back or resolve reviewed drift before accepting synchronization. |
| `Unsupported` | Keep the refusal; use a supported configuration or explicitly qualified adapter. |

Unknown causes retain their original operation reason (for example PlanRejected).
A number or word such as "403" in an arbitrary error string never grants a
typed permission diagnosis. No failure advances the last proven applied generation.

## Rotation and audit refusal

`RotationFailed`, `SecretRotationFailed`, `SecretRotationRecoveryRequired`,
`CredentialRotationReady=False` and `AuditRecorderUnavailable` require preserving
the current Secret, pending credential and recovery journal. Never delete or
manually rewrite pending/old credential fields to force Ready. Use condition
**reason**, current generation and scheduled timestamp as public diagnostics:

```sh
kubectl -n "$namespace" get hankokeycloakinstance "$instance" \
  -o jsonpath='{.status.phase}{"\n"}{range .status.conditions[*]}{.type}{" "}{.status}{" "}{.reason}{"\n"}{end}'
kubectl -n "$namespace" get hankoserviceaccount "$account" \
  -o jsonpath='{.status.nextRotation}{"\n"}{range .status.conditions[*]}{.type}{" "}{.status}{" "}{.reason}{"\n"}{end}'
```

Restore provider reachability/permissions or the configured audit recorder; allow
the same durable state machine to resume. Keycloak instance rotation tests in
`internal/controller/hankokeycloakinstance_rotation_test.go` inject failure before
promotion/audit acknowledgement and verify retry without credential loss.
`hankoserviceaccount_rotation_test.go` and `hankoapplication_runtime_test.go` test
credential/journal persistence and method-change refusal. These are controller
fixtures, **not a production rotation failover matrix**. Audit recorder outage
recovery against a real connected API remains **UNQUALIFIED**. Do not clear its
condition or acknowledge an undelivered audit locally.

If the affected IAM object is already terminating and normal recovery is
abandoned, the [audited release procedure](finalizer-recovery.md) is the only
shipped emergency finalizer path. It requires an independently approved orphaning
decision and preserves the audit failure as history. It does not acknowledge the
missing rotation receipt or clean/revoke a credential. KeycloakInstance has no
release profile in that utility; retain its pending state and repair the recorder.

## Adoption, cleanup conflicts and finalizers

For `AdoptionRequired`, `AdoptionConflict`, `CleanupConflict`, ownership loss or
incomplete inventory, preserve both native data and the finalizer. First read
public ownership UID, generation, intent/plan hashes and condition reasons; check
native dependencies with a separately authorized provider administrator. Never
change an owner marker to make a foreign resource appear owned. `System.organization_adoption`,
`System.resourceserver_adoption` and `System.cleanup_conflict` test audited adoption,
foreign/replacement dependency preservation and resume after conflict removal.
Controller adoption recovery tests cover current authority re-read before writes.

If normal recovery cannot complete and two administrators explicitly accept
orphaned provider state and Kubernetes garbage collection, follow the
[audited finalizer release procedure](finalizer-recovery.md). Its exact manifests
are in `config/recovery/`; `scripts/finalizer-recovery.py` binds a short-lived plan
to the terminating object, admission guard and cluster identities. It records
independent approval and durable intent before one selective compare-and-swap
patch. It preserves all other finalizers and never calls a provider. Do not use
`finalizers: []`. `scripts/test_finalizer_recovery.py` covers interruption, stale
authority, expiry and recorder failures; `api/v1alpha1/finalizer_recovery_integration_test.go`
and `scripts/finalizer-recovery-fixture.py` exercise authenticated admission and
the actual CLI on the supported Kubernetes API matrix. This API qualification
does not certify native cleanup, connected audit recovery or production HA.

The existing V2 ResourceServer `spec.mode: Observe` path withdraws lifecycle
consent without provider cleanup; see [existing-Keycloak adoption](architecture/existing-keycloak-adoption.md).
It remains separate from the independently approved emergency release procedure.

## Fleet plans, lifecycle approval and delegation

`FleetSignatureInvalid`, expiry, sequence rollback, target mismatch, revoked trust,
local pause or another plan-verification refusal must stop mutation. Preserve the
last checkpoint and local pause. Ask the authorized plan issuer/local trust owner
to produce a fresh signed plan bound to the intended target and current sequence.
Never lower the checkpoint, extend expiry locally or set trust from remote input.
`TestSignedFleetPlanControllerRecovery` and `scripts/fleet-installed-test.py` test
interruption, stale cache, trust revocation and safe recovery. The fleet plan
runbook in [secure deployment](secure-deployment.md) provides the exact trust/plan
ConfigMap schemas; raw signed envelopes are not suitable for incident uploads.

Experimental lifecycle requests wait for independent approval by default and
remain disabled in the chart. `System.approve_lifecycle` and `System.lifecycle_alias`
test author/operator approval denial, current generation/source UID binding,
revocation and same-child restart recovery. The administrator-only helper prints
a patch without granting permission:

```sh
kubectl -n "$namespace" get hankooperation "$operation" -o json \
  | python3 scripts/lifecycle-approval.py > "$private_approval_patch"
```

The helper reads the current Authorized=False/ApprovalRequired condition and
validates its bound source UID, generation and digest. Inspect private output
before applying under your independent administrator identity.
It is **UNQUALIFIED** for managed Upgrade, DBSwitch or source-database Clone.
Stock Keycloak refuses bounded delegation. The explicitly installed, pinned
[experimental extension](architecture/delegation-and-agent-identity.md#installed-qualification-gate-71)
implements the software profile on the reviewed versions. Check its capability
and the matching runtime/JAR evidence before enabling it; an unavailable extension
must retain `DelegationUnsupported`. Never edit the native
Prepared/Applied/Verified/Committed journal, synthesize Ready or change a federated
authenticator to recover a grant. Restore provider/authority access and let the
same owned transaction resume. The installed delegation fixture exercises each
accepted-write/restart boundary, then post-commit status loss; the complete current
matrix remains **UNQUALIFIED** in #71 after the retained failed recovery cell.
Withdrawal stops new exchanges; an offline delegated JWT remains valid until its
bounded expiry. Do not promise immediate revocation at an offline resource server.

For a terminating supported IAM resource whose cleanup cannot resume, use the
[audited release procedure](finalizer-recovery.md) only after reviewing the
orphaned grants and their remaining expiry. It never repairs signed-plan
verification, resets a checkpoint or releases a Tenant/Operation/Snapshot.
An unavailable Hub, credential refresh or mesh endpoint requires restoring the
approved endpoint, trust and scoped authority; preserve the tenant identity and
last verified plan. Live connected recovery remains **UNQUALIFIED**.

## Decommission

The tenant decommission path must retain authenticated target binding and current
local authority. `internal/controller/hankotenant_decommission_test.go` and decommission package tests exercise refusal and ordered cleanup;
installed connected decommission is **UNQUALIFIED**. Review each owned native
object and use the normal audited deletion path. Helm uninstall alone neither
proves provider cleanup nor authorizes deleting CRDs, audit evidence or Secrets.
Do not remove a namespace to make stuck finalizers disappear.

Inspect only bounded decisions while the authenticated Hub command executes:

```sh
kubectl -n "$namespace" get hankotenant "$tenant" \
  -o jsonpath='{.status.phase}{"\n"}{range .status.conditions[*]}{.type}{" "}{.status}{" "}{.reason}{"\n"}{end}'
```

`DecommissionExpired` requires a new authorized command with a fresh validity
window from the existing issuer. `DecommissionBlocked` requires repairing the
reviewed transport release/namespace and dependencies; `DecommissionFailed`
retains the command for issuer-controlled redelivery. The exact window and
deadline rules are in [secure deployment](secure-deployment.md). The controller
fixture covers these decisions; a complete live connected teardown remains
**UNQUALIFIED**. Do not synthesize a Hub confirmation or surrender credentials
before the authenticated receipt. The finalizer release utility does not support
Tenant or transport decommission.

After independently confirming owned-resource cleanup and retaining private
audit evidence, remove only the selected operator Helm release:

```sh
helm uninstall "$release" --namespace "$namespace" --wait --timeout 180s
```

`scripts/system-test.py` uses `System.cleanup` to remove its entire disposable
fixture, not this production uninstall sequence. The standalone uninstall command
above is **UNQUALIFIED** as a provider decommission procedure. Keep CRDs, shared
trust, Secrets, audit records and other releases under their existing ownership
processes.

## Incident evidence without secrets

Collect only explicitly selected public fields: source/image digest, chart
version, Kubernetes/provider versions, timestamps, resource kind/namespace,
condition type/status/reason/current generation, counts, lease holder and metrics
with their bounded labels. Treat object names and Event involved-object metadata
as internal operational data. Keep a private incident identifier and access log.

```sh
kubectl -n "$namespace" get deployment "$deployment" \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
kubectl -n "$namespace" get hankoapplication "$application" \
  -o jsonpath='{.status.phase}{" "}{.status.observedGeneration}{"\n"}{range .status.conditions[*]}{.type}{" "}{.status}{" "}{.reason}{"\n"}{end}'
```

These jsonpath selections are exercised by the runbook command fixture. Never
upload Secrets, kubeconfig, tokens, environment, raw CR specs/annotations, Helm
values, provider bodies, full Pod descriptions or unfiltered logs/status messages.
The installed fixtures inject credential sentinels and scan logs, Events and all
Hanko CRDs; the observability fixture also scans actual scraped metrics. This is a
regression check, not blanket permission to publish raw logs. Preserve incident
evidence privately; security escalation follows [SECURITY.md](../SECURITY.md).

For a report that can be reviewed without exposing resource identity or arbitrary
provider text, select the affected Hanko objects and use the offline collector:

```sh
kubectl -n "$namespace" get hankoapplication "$application" -o json \
  | python3 scripts/incident-evidence.py --output "$new_private_incident_file"
```

`scripts/test_incident_evidence.py` exercises the actual CLI, exclusive mode-0600
creation, symlink refusal, credential sentinels, unknown decisions, malformed
input, duplicate keys and size/depth/object limits. The collector makes no API or
provider calls. It accepts only reviewed Hanko resource versions, at most 2 MiB,
1,000 selected objects and nesting depth 64. Select fewer objects if refused;
do not save a raw dump to bypass its limit. Existing output paths are refused.

The output contains fixed kind/version/phase/condition decisions, bounded generation
numbers, a deletion flag and finalizer counts. Names, namespaces, UIDs, spec,
annotations, journals, messages and timestamps supplied by objects are omitted.
Unknown condition types/reasons/phases become `Other`; unknown resource versions
and Secret/ConfigMap/Event/Pod inputs are refused. Object numbers correspond only
to input order; keep their mapping privately. A stale condition is explicitly
marked non-current. This is evidence about the selected input, not proof of a
complete cluster inventory, native cleanup or administrator approval. Review even
this filtered report before sharing it; do not attach the raw input or command errors.


### Managed realm waits for explicit child cleanup

`Reconciling` on a terminating realm with `Synced=False/DependenciesRemain` preserves the provider realm
until every namespace-local realm reference is gone, including roles,
organizations, resource servers, shared workload trust and tenants. The status
contains counts by kind; remove those declarations explicitly in dependency
order. Observe declarations also block deletion of their managed parent.
Unchanged waits retry every 30–35 seconds without rewriting status. An API list
or authority recheck failure refuses provider deletion; repair access and allow
normal reconciliation. Do not force-remove finalizers to bypass this guard.
See [the installed recovery scenarios](recovery-and-realm-deletion.md) for the
five-minute operator API outage and lost realm DELETE acknowledgement tests.
These cover selected checkpoints and do not establish full production HA.
