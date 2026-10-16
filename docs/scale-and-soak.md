# Installed scale, soak and leader recovery

This development fixture addresses #95 and part of #96. It installs the actual
chart and scanned, exact-source OCI image on disposable kind and real HTTPS
Keycloak. Passing a short fixture does not qualify production capacity, all six
supported cells, a 24-hour soak, or every transaction journal.

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
serializes a queued object key; this does not serialize distinct objects with
conflicting external intent. Existing ownership guards remain necessary.

The credential budget remains eight in-flight operations and 50 requests/second
with burst 50 **per connection and process**. Replicas and separately constructed
credential connections do not share a global limiter. Resource defaults are
unchanged pending measured sizing. Organization and Issuer primary watches now
ignore status echoes; generation, reconcile requests, deletion and authority
label presence/value changes still enqueue work. Periodic reconciliation remains.

## Scenarios and measurements

The driver provisions dedicated target-realm permissions, creates realm, role
and organization fixtures, and submits an application burst. It terminates the
actual lease holder while application workers are active, requires a different
leader and two Ready replicas, then checks convergence against current
generation and observation status. It verifies exactly one native client for
each application and preserved client UUIDs after recovery.

Separate HTTPS Keycloak 429/503 and Kubernetes API 429 injections block current
authority. A changed role cannot report current Ready while authority is
unavailable. Native state must remain unchanged while the API write is blocked;
after release, the controller must converge without manually resetting status.
Deleting an Observe realm CR must preserve the native clients. Owned-realm
cascade deletion, split brain, clock skew, a five-minute API outage and every
transaction kill point remain separate qualification work.

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
The steady interval rejects missing processes, multiple/no observed leaders,
incorrect worker configuration and reconciliation above a generous dependency
event allowance. RSS peaks and rates are observations, not leak proofs or sizing
recommendations. Provider labels, endpoints, credentials, native IDs and object
names are excluded from public measurements.

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

The output directory must be new. `report.json` records pass/fail and bounded
measurements; `samples.jsonl` retains numeric samples. A failed run remains
partial and cannot become a passing report by reusing its output directory.
SIGTERM triggers cleanup of this fixture's owned resources. No global Docker
pruning or production-resource mutation is performed.
