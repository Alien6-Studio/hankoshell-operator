# IAM queue recovery and dependency fanout

Runtime source: `824c8f17db1654bdf4bc9744522ba76059350db7`.
The [OCI summary](oci-summary.json) identifies the exact scanned amd64/arm64
image. Measurements use disposable single-node kind clusters and dev-file HTTPS
Keycloak; they do not establish production capacity.

## Changes

- Four IAM controllers put successful periodic work in background priority
  -200. Cold initial-list work, live changes and error recovery share FIFO
  priority 0, so a recovery does not wait behind a thousand periodic resyncs
  and live events cannot starve cold startup. The upstream queue retains key
  serialization, coalescing, delays and the existing exponential/global retry
  limiter. Worker and credential budgets are unchanged.
- Realm status writes no longer fan out to Application and ServiceAccount
  default-policy consumers. ResourceServer ignores status-only changes of its
  spec-based Realm/Application/ServiceAccount references. Spec, UID, authority
  labels, manual requests and deletion still wake consumers. Organization
  provider identity and current Synced evidence remain significant.
- The installed load driver atomically persists numeric progress and measures
  all six convergence phases. Its unchanged 900-second default budget includes
  sampling and status reads; a late successful read cannot pass the deadline.

## Source qualification

[Source results](source-results.json) record **2,387 Go race tests**, all coverage
floors, **331 Python tests**, chart, architecture, ordinary/tagged lint and
vulnerability checks. Real Kubernetes **1.35.0, 1.36.2 and 1.37.0** each passed
**279 tests**; real HTTPS Keycloak **26.7.5 and 26.8.0** each passed **32 core
tests**. The Go suites and image use the exact runtime source above.

Queue tests exercise the actual upstream queue with 1,000 periodic/cold keys,
continuous live wakes, delayed promotion, duplicate coalescing, per-key locking
and retry backoff. The installed fixtures exercise the actual manager.

The [initial Python failure](initial-python-mutation-failure.json) is retained.
Only the negative test's obsolete observer-call pattern changed in
`c5c67871b71e822620199f25472349efbb4cc44a`; the complete Python/static group then
passed. Runtime, chart, dependencies, Go tests and installed harnesses are
byte-identical between those two commits.

The later CI follow-up is identified in `source-results.json`. It adds an
opt-in six-cell scale matrix to the already registered CI workflow, reusing
that run's exact scanned OCI archive. A requested matrix must succeed in the
required aggregate gate; an unrequested matrix must be skipped. Every existing
gate remains required. The complete 331-test preflight and Actionlint pass.
These workflow/version-sync/qualification-test changes do not change runtime,
chart, dependencies, Go tests or installed harnesses.

## Installed qualification

The [installed smoke](installed-smoke.json) passed on the exact image,
Kubernetes 1.37.0 and Keycloak 26.8.0: 40 applications, leader replacement,
all three overload/recovery scenarios, 90 measured steady seconds, exactly
40 accepted native client creates, preserved client identities and cleanup.
Measured recovery was **2.529 seconds** after Keycloak 429, **4.990 seconds**
after Keycloak 503 and **2.447 seconds** after API 429. These are single-run
observations on this small profile, not latency guarantees for 1,000 objects.

The [full installed system](installed-system.json) also passed twenty checks,
six public fixtures and [nine operational checks](../../../operations/2026-10-17/observability-runtime-824c8f1.json)
on this image. The active operational proof references this fresh completed run.

The [1,000-application intermediate snapshot](mixed-running.json) retains the
actual current phase and current-generation counts. All **1,000 applications**
passed current-generation convergence after leader replacement in **665.387
seconds**, within the unchanged 900-second budget. The final mixed fixture
must also pass all recovery, steady-state, create-audit and cleanup checks.
An intermediate phase or an active process is not a passing fixture.

The [previous runtime's final failure](previous-429-deadline-failure.json)
supersedes its earlier running snapshot: initial creation of 1,000 applications
and leader replacement passed, but recovery after global Keycloak 429 exhausted
the 900-second budget. Its fixture cleaned up successfully. Later 503/API429,
accepted-create audit and steady-state checks were not reached in that run.
The [older heavy soak's setup](previous-heavy-soak-setup-failure.json) also
failed its convergence deadline and cleaned up, before the measured soak
interval started. It is not 24-hour evidence.

## Remaining qualification

Issue #95 stays open until the required matrix, larger per-kind bounds, owned
realm cascade deletion, measured resource defaults and a completed **24-hour**
soak are available. A [new minimum-24-hour fixture](soak-start.json) is running on this runtime
with 10 realms, 1,000 applications, 100 roles, 100 organizations and 20 resource
servers. Setup and recovery must pass before its measured interval starts.
Existing long runs remain evidence for their own source revisions.
No new worker default, production sizing, publication or completed
24-hour claim follows from this packet.
