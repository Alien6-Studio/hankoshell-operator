# Six-cell scale matrix and unfinished larger/endurance qualification

Runtime: `a65f15791956e750b9f629374b7554b0da20788f`.
[Full CI 39162719045](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39162719045)
finished with **55 successful jobs, three failures and one skipped job**.
All six scale jobs passed. Two installed delegation cells failed; the required
aggregate correctly failed. This packet does not attest a passing full gate.

## Passing CI profile

Each cell uses 10 realms, 1,000 applications, 100 roles, 100 organizations and
20 resource-server grants, four IAM workers and the unchanged 900-second phase
budget. Each retains 14 scale assertions, the separate owned-realm/API-outage
recovery report and the journaled transaction report. OCI identity is
`sha256:17d746ee4af707da6f7d577b26a71bfa9f348d1b3d5c257f3bc199c1acfc5608`.

| Keycloak | Kubernetes | Apps after leader loss (s) | Steady (s) | Observed RSS peak (MiB) | API starts/s | Provider requests/s |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 26.7.5 | 1.35.0 | 863.512 | 302.457 | 156.6 | 58.40 | 50.19 |
| 26.7.5 | 1.36.2 | 667.296 | 301.677 | 162.0 | 61.52 | 50.11 |
| 26.7.5 | 1.37.0 | 683.757 | 302.643 | 159.5 | 60.10 | 50.14 |
| 26.8.0 | 1.35.0 | 846.176 | 302.597 | 158.6 | 58.55 | 50.15 |
| 26.8.0 | 1.36.2 | 713.970 | 302.985 | 162.5 | 59.76 | 50.11 |
| 26.8.0 | 1.37.0 | 707.736 | 302.958 | 166.3 | 59.94 | 50.11 |

These are measurements of a disposable single-node environment, including both
operator replicas. Histogram latency bounds and per-kind reconcile counts remain
in each `scale.json`. A null latency bound is unestablished. The short interval
passes the fixture's generous no-hot-loop ceiling, not the 24-hour requirement
or a production sizing recommendation. Chart resource/worker defaults are unchanged.

## Failed larger local profile

`larger-capacity-failed.json` uses the same exact runtime with a separate locally
scanned OCI `sha256:b62ecbc9937545d3f2c8d3aedbb3b13589f51a98e0e511f372abd3699687b600`.
It requested 100 realms and 1,000 each of applications, roles, organizations and
grants on Keycloak 26.7.5 / Kubernetes 1.36.2. All realms, roles, organizations
and applications reached current readiness, with no manual reconcile wake or
status reset. Initial dependencies took 400.146 s; applications after planned
leader loss took 1,666.840 s under this explicit 3,600-second experimental budget.
The authorization phase failed at 3,603.528 s with only 408/1,000 grants current.
Cleanup completed. This is a failing capacity attempt, not a bound qualification.

## Failed older endurance interval

`older-379ea9d-soak-failed.json` belongs only to runtime
`379ea9db5673e2d871aca7bdde20b4fa9480b18a`, with its separate scanned OCI recorded
in the report. It stopped after 37,498.606 measured steady seconds (10 h 24 m
58.606 s), 3,454 steady samples and zero lost process epochs during the interval.
The runner rejected a sampling gap above 45 s. The old report does not retain
the offending wall/monotonic pair, so host sleep, clock change and collection
latency are not distinguished. `complete` and `soak.qualified` remain false;
cleanup completed. It does not qualify the newer runtime or 24-hour endurance.

#95 remains open for larger capacity, complete endurance and measured resource
sizing. Raw samples and bounded diagnostics remain in the local ignored bundle;
retained public reports have recursive SHA-256 integrity records.
