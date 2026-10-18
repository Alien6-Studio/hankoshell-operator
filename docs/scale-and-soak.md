# Installed scale, soak and leader recovery

This development fixture addresses #95 and part of #96. It installs the actual
chart and scanned, exact-source OCI image on disposable kind and real HTTPS
Keycloak. Passing a short fixture does not qualify production capacity, all six
supported cells, a 24-hour soak, or every transaction journal.

The [2026-10-17 queue recovery packet](qualification/scale/2026-10-17/runtime-824c8f1/README.md)
records the queue-recovery source, source checks, installed results and
remaining qualification. Its predecessor's final 429 deadline failure is
retained alongside the new measurements.

The [later realm-deletion and API-recovery packet](qualification/recovery/2026-10-17/runtime-64e4890/README.md)
records the newer runtime and its separate recovery qualification.

## Bounded IAM workers

`reconciliation.maxConcurrent` defaults to **1**. Explicit integers **1–8** set
`HANKO_IAM_MAX_CONCURRENT_RECONCILES` for these controllers only:

| Controller | Shared-state review |
| --- | --- |
| Application | Per-request working objects; synchronized connection pool |
| Role | Per-request working objects; immutable shared HTTP client |
| Organization | Per-request working objects; immutable projection configuration |
| ResourceServer | Per-call resolver copy and organization-grant cache |

The runtime rejects empty, noncanonical and out-of-range values before controller
registration. The chart rejects an environment override that would bypass the
typed setting. All other controllers retain one worker. Controller-runtime
serializes a queued object key. For these four controllers, cold initial-list
events and live changes use the same FIFO priority **0**. Successful periodic
resyncs (at least 30 seconds) use background priority **-200**. Errors and short
checkpoints return to priority 0, so recovery does not wait behind a thousand
background resyncs. Upstream initial-list priority -100 is normalized to 0;
simply enabling the default priority queue would starve cold recovery again.
Organization ownership refusals also retain explicit priority 0 with their
unchanged 30–35-second delay, even though they return no Go error. Pending
children must not starve the fresh ownership read needed after an ambiguous
create. The scheduler preserves that explicit priority; an actual Go error
always returns to priority 0. The real-queue regression exercises the controller's
ownership-refusal path with 1,000 waiting children. No owner check is bypassed.
The upstream queue still owns synchronization, delayed work, coalescing and
per-key serialization; the existing exponential/global retry limiter is retained.
There is no new worker pool or provider budget. This does not serialize distinct objects with
conflicting external intent. Existing ownership guards remain necessary.

Observation traffic is bounded within each attempt. A settled non-composite role
uses one complete provider read; drift still triggers mutation and independent
read-back. Application child reads use the physical UUID from the same attempt's
exact lookup/full client read, so replacing a client cannot splice different
clients into one observation. No provider snapshot is cached between attempts.

Application/ServiceAccount ownership lists remain uncached and namespace scoped,
with `spec.realmRef` filtered at the API server. They deliberately do not filter
`clientID`, because legacy whitespace aliases must still collide. The updated
CRDs declare that selectable field; **apply both CRDs before upgrading the
controller**, including for Helm upgrades, which do not upgrade files under
`crds/`. Missing server-side selector support fails the ownership check closed.
This uses the supported Kubernetes field-selector contract, stable since 1.32
([Kubernetes documentation](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)).

The credential budget remains eight in-flight operations and 50 requests/second
with burst 50 **per connection and process**. Replicas and separately constructed
credential connections do not share a global limiter. Resource defaults are
unchanged pending measured sizing. Organization and Issuer primary watches now
ignore status echoes; generation, reconcile requests, deletion and authority
label presence/value changes still enqueue work. ResourceServer dependency
watches retain group identity/path/current Synced changes while ignoring Role
observation times and optional organization projection updates. Realm,
Application and ServiceAccount references consume spec/identity/authority and
ignore status-only updates. Realm default-policy consumers also ignore realm
status writes; spec, manual requests, authority and deletion remain immediate
wakes. Periodic reconciliation remains. A resync interval is not a guaranteed
per-object service deadline under a saturated provider budget.

## Scenarios and measurements

The driver preprovisions realms with dedicated target-realm permissions, manages
those parents explicitly during load, and creates realm, role
and organization fixtures, and submits an application burst. It terminates the
actual lease holder while application workers are active, requires a different
leader and two Ready replicas, then checks convergence against current
generation and observation status. It verifies exactly one native client for
each application and preserved client UUIDs after recovery.

Separate HTTPS Keycloak 429/503 and Kubernetes API 429 injections block current
authority. A changed role cannot report current Ready while authority is
unavailable. Native state must remain unchanged while the API write is blocked;
after release, the controller must converge without manually resetting status.
Switching the selected parent explicitly to Observe and waiting for its Observe
checkpoint before deleting the realm CR must preserve the native clients. Owned-realm
cascade deletion uses explicit child-first cleanup. The separate
[recovery fixture](recovery-and-realm-deletion.md) exercises a managed realm with
222 dependents, lost DELETE acknowledgement, leader replacement and a five-minute
operator API transport outage. Split brain, clock skew and every transaction
kill point remain separate qualification work. Only retained actual results
qualify either fixture.

| Profile | Realms | Applications | Roles | Organizations | Resource servers | Steady interval |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| smoke | 2 | 40 | 8 | 8 | 2 | 90 seconds |
| scale | 10 | 1,000 | 100 | 100 | 20 | 300 seconds |
| soak | 10 | 1,000 | 100 | 100 | 20 | at least 86,400 seconds |

Counts and duration are explicit command options. A soak below 24 hours is
rejected, and `soak.qualified` requires the actual measured interval to reach
24 hours. This is a fixture result, not production evidence.

Metrics use a private CA and authorized SPIFFE client over TLS. The parser retains
only bounded numeric values: API request starts, provider requests, CPU, RSS,
heap, goroutines, controller activity and reconcile latency buckets. API request
starts are not watch-event counts. The reported p95 is a histogram upper bound;
`null` means there were no observations or the bound was infinite.

Process epochs distinguish restarts from counter resets. Lost processes during
intentional failover are recorded; counters across that phase are lower bounds.
The steady interval rejects sampling gaps above 45 seconds in both monotonic
and wall time, missing processes,
multiple/no observed leaders,
incorrect worker configuration and reconciliation above a generous dependency
event allowance. RSS peaks and rates are observations, not leak proofs or sizing
recommendations. Provider labels, endpoints, credentials, native IDs and object
names are excluded from public measurements.

A process-epoch loss stops the interval at the first affected sample. Host sleep
or a wall-clock rollback cannot qualify through a short monotonic gap. Failed
intervals retain numeric elapsed time, sample and lost-process counts in
`steady_observation`, with `complete: false` and `soak.qualified: false`.
The retained [824c8f1](qualification/scale/2026-10-17/runtime-824c8f1/soak-final.json)
and [64e4890](qualification/recovery/2026-10-17/runtime-64e4890/soak-final.json)
endurance reports are failures, superseding their running snapshots. Neither
provides 24-hour evidence; the cause of their provider 401 responses and
process-epoch changes is unresolved.

## Run against an immutable checkout

The driver verifies OCI security evidence before creating resources and requires
a clean checkout at the exact supplied source SHA throughout the measurement.
Use an isolated clean worktree for a long soak so ordinary development cannot
invalidate it. Docker and sufficient host capacity must remain available.
Fixture certificate validity includes the requested duration and setup margin.

```sh
make scale-installed-test \
  OCI_ARCHIVE="$archive" OCI_EVIDENCE="$evidence" \
  OCI_DIGEST="$digest" REVISION="$revision" \
  KIND="$kind" KUBECTL="$kubectl" HELM="$helm" ORAS="$oras" OPENSSL="$openssl" \
  SCALE_PROFILE=smoke SCALE_WORKERS=4 \
  SCALE_OUTPUT="$fresh_output_directory"
```

Use `SCALE_PROFILE=scale` for the thousand-application burst or `soak` for the
24-hour minimum. Consult `make -n scale-installed-test` for tool/version options.
The manual `Installed scale qualification` workflow covers the six pinned
Kubernetes/Keycloak cells for short profiles. Hosted jobs do not claim a 24-hour
soak; run that profile on a persistent disposable runner.

Before this new workflow exists on the default branch, invoke it through the
existing CI workflow on the development ref:

```sh
gh workflow run ci.yml --ref feat/1.0.0-dev -f qualify_scale=true
```

This opt-in adds the six-cell 1,000-application matrix alongside the full normal
CI, including the owned-realm/API-outage recovery fixture using the same scanned
archive. Ordinary CI runs keep their existing qualification gates and workload.

The output directory must be new. `report.json` records pass/fail and bounded
measurements; `samples.jsonl` retains numeric samples. Atomic `progress.json`
snapshots expose the current phase, numeric current-generation object counts
and elapsed convergence/recovery durations without object names or raw status.
Use the final `report.json` for the verdict: an intermediate phase completion
does not complete the fixture. Each phase retains its 900-second default budget;
completion after the deadline, including sampling/status reads, is refused.
Phase timing includes queue waiting, which the reconcile duration histogram
does not. A failed run remains
partial and cannot become a passing report by reusing its output directory.
SIGTERM triggers cleanup of this fixture's owned resources. No global Docker
pruning or production-resource mutation is performed.
