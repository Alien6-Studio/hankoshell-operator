# Operational observability contract

This initial development contract applies to the v1alpha1 operator. It does not
qualify stable APIs, production HA, a 24-hour soak, a running Prometheus Operator,
or CNI enforcement. The [runbooks](operations-runbooks.md) distinguish tested
recovery from procedures awaiting qualification.

## Secure metrics

Metrics are off by default. Enabling them requires server `tls.crt`/`tls.key`,
a client CA `ca.crt`, and 1–16 distinct exact SPIFFE URI SAN identities. The binary
requires `--metrics-cert-dir`, `--metrics-client-ca`, `--metrics-client-uris`
alongside a nonzero `--metrics-bind-address`. There is no plaintext or anonymous
mode. TLS 1.3, trusted client chain/clientAuth usage, certificate validity and an
allowlisted URI are mandatory. Certificate CN and bearer headers grant no access.

Example pre-existing Secret names (never put private keys into values files):

```yaml
metrics:
  enabled: true
  tls:
    serverSecret: metrics-server
    clientCASecret: metrics-client-ca
    allowedClientURIs:
      - spiffe://monitoring.example/prometheus/platform
  serviceMonitor:
    enabled: true
    labels:
      release: prometheus-stack
    serverCASecret: metrics-server-ca
    clientSecret: prometheus-client
  networkPolicy:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: monitoring
    podSelector:
      matchLabels:
        app.kubernetes.io/name: prometheus
        prometheus: platform
```

All four Secrets are in the release namespace. The server certificate SAN must
include `<operator-fullname>-metrics.<release-namespace>.svc`. The server/client CA
Secrets contain `ca.crt`; both identity Secrets contain `tls.crt` and `tls.key`.
The Prometheus Operator must be allowed to read its selected client Secret in
that namespace. Use an independent monitoring CA and restrict writes to these
Secrets and the Deployment to platform administrators. The operator's existing
namespace-scoped Secret privileges are not expanded; compromise of that identity
remains outside the protection supplied by transport authentication.

The ServiceMonitor verifies the server DNS identity and CA and supplies its
client certificate; no `insecureSkipVerify` exists. Install the ServiceMonitor
CRD first. Without ServiceMonitor, configure equivalent mTLS in your scraper;
annotation discovery is no longer advertised. NetworkPolicy still requires a
single peer combining the exact Prometheus namespace AND pod labels on TCP/8080.
Other additive network grants and the actual CNI must be checked per installation.

Every new handshake reloads bounded Secret files (64 KiB each); missing, corrupt
or mismatched projected files fail closed. TLS session resumption is disabled.
Allow up to the Kubernetes Secret projection delay for changes to reach a pod.
Rotate trust with a reviewed overlap, then remove the old CA; existing connections
are not terminated by trust reload. There is no cross-namespace auth delegation,
TokenReview/SAR permission, self-signed certificate fallback or public exposure.

## Metrics and label bounds

The machine inventory is [operational-contract.json](operational-contract.json).
Names are frozen for this development contract; additions need a reviewed
inventory update. Labels contain only the following finite vocabularies:

| Family | Labels and meaning |
| --- | --- |
| `hanko_operator_reconcile_total` | `kind`: 17 registered Hanko kinds + `other`; `outcome`: success, requeue, error, panic, other |
| `hanko_operator_reconcile_duration_seconds` | kind; one completed attempt, including status patches |
| `hanko_operator_provider_requests_total` | provider: keycloak, authentik, other; method: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, other; outcome: 2xx, 3xx, 4xx, 5xx, transport_error, other |
| `hanko_operator_provider_request_duration_seconds` | provider/method; HTTP attempt and bounded response read; refused local preconditions do not issue a request |
| `hanko_operator_verification_total` | domain: iam, fleet, image, other; outcome: accepted, refused; IAM role/resource-server evaluation decisions, signed fleet verification and image approval/signature verification |
| `hanko_operator_events_total` | 15 catalog reasons; type: Normal, Warning, other; submitted Events, not persisted acknowledgements |
| `hanko_operator_instances` | state: ready, degraded, pending; reported phase, not current-generation rollout proof; leader-only bounded inventory |
| `hanko_operator_rotations` | kind: Application, ServiceAccount or KeycloakInstance (full Hanko kind names); state: scheduled, overdue, failed |
| `hanko_operator_rotation_overdue_seconds` | same three kinds; maximum elapsed time past next scheduled rotation |
| `hanko_operator_inventory_complete` | no labels; 0 invalidates counts, 1 complete sample |
| `hanko_operator_leader` | no labels; 1 only after this running manager acquired its lease |

Histograms use the 11 Prometheus default finite buckets plus `+Inf` and sum/count.
At most **892 custom time series per process**, including every fallback and
histogram series. Arbitrary provider strings, kind names and errors collapse to
`other`; native identifiers, CR names/UIDs, realms, namespaces, URLs, Secret names,
credential contents and plan hashes never label a custom metric. Scraper-added
job/instance/namespace/pod labels are external deployment identities and must
also have retention/cardinality policies. Existing controller-runtime, Go and
process metrics remain upstream-defined and are not covered by this custom bound.
No tracing, pprof, configuration dumps or raw provider response logging is enabled.

Every 30 seconds the elected replica lists at most 1,000 objects of each of
KeycloakInstance, Application and ServiceAccount, within its watch namespace and
a shared 10-second deadline. No Secret is read and no object is retained after
the sample. Any error, continuation or over-limit result drops all old counts and
sets completeness to 0. This is a diagnostic ceiling, not a supported scale claim;
more than 1,000 objects of one kind requires the scale qualification in #95.
Rotation gauges classify enabled schedules; an overdue timestamp contributes to
oldest-overdue even when the state is failed. They do not count unpublished
intermediate credentials or prove successful audit delivery. Missing schedules
are reported as scheduled, never as proven successful rotations.

## Events and bounded diagnostics

Only the reviewed reasons/messages in `internal/observability/events.go` can
leave the process recorder. Caller-supplied message text, format arguments,
provider body, reason, event type and action cannot introduce arbitrary Event
text. Unknown reasons become `UnclassifiedEvent`, unknown actions `Reconcile`,
and unknown types `Warning`. Kubernetes involved-object metadata still identifies
the resource; administrators must treat Events as operational data. Theme and
tenant failures use stable `ThemeReconcileFailed` and `TenantReconcileRefused`;
inspect the condition reason for detail. This replaces dynamic Event reasons.

Keycloak error responses are fully bounded before their bodies are discarded at
the HTTP gateway. Typed `StatusError` carries only HTTP status; classification
uses `errors.As`, never an error-string match. Transport errors become fixed sentinels. TLS certificate verification retains
a typed `ErrTLSVerification` category alongside `ErrTransport`, while discarding
native certificate identities and transport diagnostics. 404/409 idempotence branches remain caller-specific. Authentik already
uses fixed typed status/transport errors. Logs and public statuses receive these
safe errors rather than native credential-bearing error bodies. This does not
turn arbitrary existing Kubernetes error text or administrator-authored CR fields
into public information: evidence collection must select fields explicitly.

## Health, readiness and leader semantics

`/healthz` is process liveness, independent of provider availability and leadership.
`/readyz/serving` means manager/cache startup completed; it is withdrawn on stop.
`/readyz/leader` requires serving plus lease acquisition. `/readyz/keycloak`
checks the configured provider with a five-second deadline and a fixed failure
message (absent in spoke mode). `/readyz` aggregates these checks and is therefore
**reconciliation readiness**: standby replicas fail it intentionally.

The Pod readiness probe uses `/readyz?exclude=leader`, retaining the provider
check while allowing a healthy standby to stay Ready. This permits rolling
updates and Service scraping on all replicas. It does not imply the standby can
reconcile. Loss of the lease stops the manager under controller-runtime semantics;
the leader gauge resets during shutdown. Multi-replica failover, partition and
soak proof remain #96/#95, not a claim established by a probe implementation.

## Alerts and dashboard

[alerts.yaml](../config/prometheus/alerts.yaml) is an opt-in PrometheusRule example;
[observability-dashboard.json](observability-dashboard.json) is an importable
Grafana dashboard. Set its job variable to the actual scrape job. Review alert
thresholds against your reconciliation budget and configure target-down/absent
scrape alerts in Prometheus itself. Examples cover degraded instances, verification
refusals, overdue rotation, incomplete inventory, absent leadership and hot loops.
They contain no resource identity labels. These examples are checked as source;
a running Prometheus/Grafana deployment remains installation-specific.

## Qualification

`TestMetricsMutualTLSAuthenticatesAuthorizesAndReloadsTrust` tests actual TLS
handshakes (approved, anonymous, wrong URI, foreign CA, expired, TLS 1.2, CA
revocation and invalid trust). `TestMetricsCardinalityAndSecretSentinels`,
`TestEventsDiscardUntrustedTextAndBoundReasonVocabulary` and
`TestKeycloakErrorsAreTypedAndNeverIncludeNativeDiagnostics` inject sentinels.
`TestServingAndLeaderReadinessAreIndependent` covers standby/start/stop semantics.
Chart observability tests check exact mTLS mounts/arguments, ServiceMonitor trust,
absent annotations and conjunctive ingress. `scripts/observability-installed-test.py`
qualifies the scanned OCI under real kind/Helm with authenticated scraping,
anonymous/wrong-URI refusal, bounded metrics and current lease/standby probes.
The full installed system fixture also executes that observability scenario.
A report is evidence only for its recorded source/image/harness versions.

The [retained installed smoke report](qualification/operations/2026-10-16/README.md)
binds the exact scanned runtime and harness hashes; the release contract rejects
altered, failed or stale-harness evidence. Full matrix qualification remains CI.
