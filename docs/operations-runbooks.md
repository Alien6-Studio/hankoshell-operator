# Operator operational runbooks

This is an **initial development** runbook for the v1alpha1 API, before the first
public release. No predecessor-to-public upgrade, production HA, production storage migration,
bounded delegation recovery or connected installation is qualified. Do not infer
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

**UNQUALIFIED: connected installation.** The enterprise/Continuum Helm renders and
transport refusal tests exercise configuration guards; no live Hub/Continuum
end-to-end installation is proven here. Follow the enterprise prerequisites in
the secure deployment guide and qualify your deployment separately. Do not reuse
a standalone fixture as evidence of a connected installation.

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

For development chart configuration changes only, the installed observability
fixture exercises a real Helm upgrade and rollback to previous reviewed values:

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
The installed observability fixture starts two replicas, proves exactly one lease
holder, verifies standby probe semantics, removes that leader and observes a new
holder with the same native managed client and credential. This is a bounded
single-node smoke test. **UNQUALIFIED: network partition, split brain, clock skew,
5-minute API outage, operation-interruption matrix and 24-hour soak** (#96/#95).

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

## Adoption, cleanup conflicts and finalizers

For `AdoptionRequired`, `AdoptionConflict`, `CleanupConflict`, ownership loss or
incomplete inventory, preserve both native data and the finalizer. First read
public ownership UID, generation, intent/plan hashes and condition reasons; check
native dependencies with a separately authorized provider administrator. Never
change an owner marker to make a foreign resource appear owned. `System.organization_adoption`,
`System.resourceserver_adoption` and `System.cleanup_conflict` test audited adoption,
foreign/replacement dependency preservation and resume after conflict removal.
Controller adoption recovery tests cover current authority re-read before writes.

**UNQUALIFIED: a generic administrator-approved, audited release-without-cleanup
workflow.** No such cross-domain command is shipped. Retain the finalizer and
record the incident for administrator review; never use `finalizers: []` as a
substitute. The existing V2 ResourceServer `spec.mode: Observe` path withdraws
lifecycle consent and releases that CR without provider cleanup, as documented
in [existing-Keycloak adoption](architecture/existing-keycloak-adoption.md).
This existing mode transition is not an independently audited emergency release
mechanism. Do not generalize it to other domains. Recovery requiring that new
approval/audit mechanism remains outstanding in #103.

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
Bounded delegation is currently refused on both qualified Keycloak versions;
**UNQUALIFIED: delegation grant/recovery/revocation** (#69–#71). Do not widen a
service-account credential or remove the refusal to simulate delegation support.

## Decommission

The tenant decommission path must retain authenticated target binding and current
local authority. `internal/controller/hankotenant_decommission_test.go` and decommission package tests exercise refusal and ordered cleanup;
installed connected decommission is **UNQUALIFIED**. Review each owned native
object and use the normal audited deletion path. Helm uninstall alone neither
proves provider cleanup nor authorizes deleting CRDs, audit evidence or Secrets.
Do not remove a namespace to make stuck finalizers disappear.

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
