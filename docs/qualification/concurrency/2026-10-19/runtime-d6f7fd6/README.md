# d6f7fd6 admission regression and final qualification results

Exact runtime: `d6f7fd66e2f6bee220ad17632d0bf4fbe7b60cae`.
[Full CI 39224363295](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39224363295)
finished with **50 successful jobs, eight failures and one skipped job**.
Six scale cells, one installed delegation cell and the required aggregate failed.
Source/security/OCI, all ordinary native suites, installed system, workload,
portable-provider, Fleet and release rehearsal jobs passed. This is a failed full
qualification, with no failed-test retry or quarantine.

## Scale and endurance

All six standard 1,000-application cells failed: four during authorization graph
convergence and two after entering steady measurement and losing current readiness.
Their complete reports remain in `scale/`. Bounded operator tails contain the
fixed error `keycloak request token became stale before I/O`; only lower-bound
counts are retained in `diagnostic-observations.json`. Detailed CR dumps exceeded
the diagnostic budget, so missing per-object causes are not inferred.

The local arm64 soak used a separately scanned OCI
`sha256:c47b2288a14287aba457fa900d39970bbd3043fa7a2a60b9bbd206382a1d378b`.
It failed setup: 18/20 grants were current at the unchanged 900-second authorization
phase deadline. All 10 realms, 1,000 applications, 100 roles and 100 organizations
were current; application recovery after leader loss took 691.178 s. Cleanup
completed. It never entered the measured steady interval and is not 24-hour evidence.

The fail-closed token-header check exposed an admission regression under expiry
or invalidation: an unsent request failed instead of releasing its HTTP slot and
renewing through the existing single flight. Independently, eight guarded writers
could reserve all eight slots and then each wait for a provider authority read.
Both paths have deterministic regression tests which fail before the follow-up
fix; no native timeout, readiness acceptance or ownership check is relaxed.
The new convergence progress format retains only fixed phase/reason counts.

## Installed delegation

Five final-source cells completed all 88 assertions and four native-phase
recoveries. Keycloak 26.8.0 / Kubernetes 1.35.0 reached 54 assertions, then timed out
waiting for the deterministic API status fault during recovery from the accepted
Prepared write. Both resource servers reported PlanRejected; masked provider
errors do not establish the entire installed failure cause. Complete reports and
the unchanged 180-second failed wait remain in `delegation/`.

The separate `local-90ad9c4/` reports completed 88 assertions/four recoveries each
on Kubernetes 1.35.0 for both SDKs. Their runtime is the earlier watch-proxy fix,
not d6f7fd6 or the following admission correction. Both runner exits were zero;
local successes do not override a failed final-source CI cell.

`source-summary.json` binds 2,699 passing race outcomes and zero failures/skips to
the clean d6f7fd6 baseline; all reviewed coverage floors passed. This does not
attribute those tests to the follow-up implementation. No publication, merge,
production sizing or complete #71/#95 acceptance is attested by this packet.
