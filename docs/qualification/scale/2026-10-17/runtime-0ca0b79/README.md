# IAM observation and ownership list costs

Runtime source: `0ca0b79f64f5a4e3edbc6ab1f5f547d91e4e0fae`.
The [OCI summary](oci-summary.json) binds the exact scanned amd64/arm64 image,
SBOM and provenance. Measurements use a disposable single-node kind cluster and
dev-file HTTPS Keycloak; they are development evidence, not production sizing.

## Changes

- A settled non-composite role uses one complete provider read per attempt.
  Composite closure failures still refuse reconciliation, and provider mutations
  retain independent read-back. Evidence is not cached between attempts.
- Application roles, scopes and protocol mappers are read using the physical
  UUID from the same exact lookup/full client read. A replacement client cannot
  splice its children into that observation. An unreadable child fails the
  entire observation; SAML still excludes OIDC mappers and secret endpoints.
- Authoritative ownership lists stay uncached and namespace scoped, with realm
  filtering performed by the API server. Client ID filtering is deliberately
  excluded so trimmed legacy aliases still conflict. Both CRDs must be updated
  before the controller; see the [upgrade preflight](../../../../operations-runbooks.md#upgrade-rollback-and-storage).

## Source qualification

[The source results](source-results.json) record **2,374 Go race tests**, all
coverage floors, **329 Python tests**, chart, lint (ordinary/tagged), architecture,
vulnerability checks and repository hooks. Both real HTTPS Keycloak core suites
passed **32 tests each**. The unit/native source is `4d4ab53`; its only follow-up
change in `0ca0b79` corrects an integration-test assertion. Runtime, CRDs, chart,
scripts and dependencies are byte-identical between those two commits.

Real Kubernetes **1.35.0, 1.36.2 and 1.37.0** each passed **279 tests** on the final
source. They exercise the actual server-side selectors, fresh realm edits and
cross-kind ownership conflicts involving whitespace aliases, with no provider
requests while conflicting.

The [initial failed API attempt](initial-api-assertion-failure.json) is retained:
the new test expected phase `Conflict`, whereas the existing service-account
contract reports `Error` with `Synced=False/OwnershipConflict`. Only the assertion
changed; all three corrected API suites passed. No failed test was quarantined.

The [installed system](installed-system.json) passed twenty checks, six public
fixtures and [nine operational checks](../../../operations/2026-10-17/observability-runtime-0ca0b79.json)
on this exact image. These include actual mTLS refusals, lease replacement and
configuration rollback. The active operational proof references this fresh run.

## Mixed load: creation passes, recovery still running

The [intermediate snapshot](mixed-running.json) records successful convergence
of all **1,000 applications** after active leader replacement, all twenty
resource servers, and exactly one current native client per application.
The 900-second convergence budget, counts, four workers and credential budget
remain unchanged from the previous attempt. The initial creation deadline that
failed on `622da8a` is now passed.

The injected provider 429 refuses current Ready as required. Recovery still has
objects queued behind the large background application backlog at this snapshot.
The accepted-create audit, later 503/API429 recovery, the five-minute steady interval and cleanup must all
finish before this mixed fixture can pass. **This is not a completed scale
qualification**; #95 remains open. The live experiment is preserved independently
of the editable development checkout.

The 30–35 second resync setting does not guarantee that every queued object is
serviced in that interval under this load. Controller duration histograms exclude
time spent waiting in the workqueue. No production latency or capacity SLO is
inferred from this run.

## Limits

This packet does not qualify production capacity, every supported scale cell,
owned-realm cascade deletion, all HA transaction journals or a completed 24-hour
soak. A new 24-hour-minimum soak is running on this runtime with the heavy profile
(10 realms, 1,000 applications, 100 roles, 100 organizations, 20 resource servers),
Keycloak 26.8.0 and Kubernetes 1.37.0. It is not qualified until completion.
The ongoing `622da8a` soak remains evidence for that older runtime only.
The previous [1,000-application deadline failure](../runtime-622da8a/unqualified-mixed-kubernetes-1.35.0-keycloak-26.7.5.json)
remains retained. The current mixed fixture keeps its 900-second convergence
budget, object counts and credential request limits unchanged.
