# Installed IAM load and recovery qualification

Runtime `622da8a3cd9046791c567143475e5bb63217fc0d`, scanned multi-architecture index
`sha256:017cb49dd8eb42760a257c93c6b46cb9580ea6d9d14a39db60394bf7b677fd6d`. Both Linux architectures passed the pinned OCI
scanner with SBOM/provenance. Local installed measurements execute arm64 on a
single disposable kind node with dev-file Keycloak. This is development evidence,
not a production capacity recommendation or a completed six-cell scale matrix.

The [source summary](source-results.json) records **2,366 Go race tests**, **329
Python tests**, both native Keycloak core suites (**32 tests each**), coverage,
preflight, tagged lint, architecture, vulnerability, chart and repository hooks.
The [installed system](installed-system.json) passed twenty checks, the six public
fixtures, and [nine operational checks](../../../operations/2026-10-17/observability-runtime-622da8a.json)
on this exact image. It includes explicit negative TLS peer-certificate alerts,
authorized scrapes on both replicas, lease recovery and configuration rollback.

## Queue and dependency fixes

Four IAM controllers accept 1–8 workers, defaulting to one; this fixture requests
four and verifies the installed worker gauges. Their queues explicitly use FIFO.
The pinned controller-runtime otherwise lowers initial-list event priority;
live dependency refreshes can keep warm cohorts ahead of cold recovery work.
FIFO preserves per-key serialization/coalescing and normal retry limits. Other
controllers retain their existing serial configuration.

Organization/Issuer primary watches ignore status echoes. ResourceServer
Organization/Role dependency watches retain spec, identity, authority labels,
deletions and current provider group/Synced changes, while ignoring observation
timestamps and optional platform projection updates. Fresh authority checks
before effects remain unchanged.

The [historical priority investigation](historical-priority-investigation.json)
was deliberately interrupted: 1,000 applications existed, 136 were Ready and 864
had no observed generation. It is **not passing scale evidence**. Historical
`0f9a26d` native outcome files also retain failed attempts during confirmed macOS
suspend/resume and transport interruptions. Their later passes do not erase those
failures. Current native reports above bind the final runtime and clean checkout.

## Short installed fixture

[The completed short fixture](smoke-kubernetes-1.37.0-keycloak-26.8.0.json) uses two
realms, forty applications, eight roles, eight organization nodes, two resource
servers and two operator replicas. It kills the lease holder during active load,
checks one accepted native client create per application and preserved identities,
injects actual Keycloak 429/503 and API 429, and proves recovery without status
reset. Explicit Observe transition before parent CR deletion preserves clients.

| Observation over approximately 90 seconds | Before dependency filtering (009f39e) | Final runtime (622da8a) |
| --- | ---: | ---: |
| ResourceServer reconciliations | 29 | 7 |
| Keycloak HTTP requests/second | 48.28 | 34.94 |
| API HTTP request starts/second | 46.67 | 43.73 |

The final ResourceServer cadence is consistent with periodic requeue plus a
window edge. [The earlier report](historical-before-dependency-filter.json) and
current report use the same object counts and versions. These short local runs
have concurrent host activity; they are not a controlled hardware sizing study.
Histograms report finite p95 upper buckets, not exact latencies. The final sample
gap stayed below 10.31 seconds; continuous measurements reject gaps above 45.
Resource/concurrency chart defaults are unchanged pending broader evidence.

## Remaining qualification

The mixed profile offers ten realms, 1,000 applications, 100 roles, 100 organization
nodes and twenty resource servers on Kubernetes 1.35.0 / Keycloak 26.7.5. Its
result is retained as [unqualified](unqualified-mixed-kubernetes-1.35.0-keycloak-26.7.5.json): it did not converge within the unchanged 900-second budget.
The [progress snapshot](unqualified-mixed-progress.json) recorded 578 Ready and
422 never-observed applications at approximately fifteen minutes. The earlier
initial-list investigation and this snapshot have different elapsed times; they
are not a throughput benchmark. The final queue is fair, but this mixed load
remains above the demonstrated bound with the fixed request budget. The passing
short fixture grants no 1,000-object capacity claim. Further provider/API work per
reconcile, scheduling pressure and queue latency require investigation under #95. Owned-parent cascade deletion and all journaled HA kill points,
partitions, clock skew and five-minute API outage remain unqualified.

[The soak start record](soak-start.json) identifies a separate **40-application**
run on the immutable source with a minimum of 86,400 measured seconds. It is
ongoing and **not qualified**. A short run or an incomplete process never becomes
24-hour evidence. See [the reproducible driver procedure](../../../../scale-and-soak.md).

[The twenty-main-run read](main-history-gaps.json) still has missing outcome
artifacts; absence is not stability. #110 retains its history requirement and
GitHub whole-job timing target. Ordinary tagged tests and static checks now run
in separate required jobs while preserving the exhaustive native/ordinary test
inventory and JUnit reporting.

The final evidence commit changes documentation only. Complete CI on its pushed
head remains required before fusion. No merge, public release or registry
publication is part of this qualification.
