# Installed delegation CI on a65f157

Exact runtime `a65f15791956e750b9f629374b7554b0da20788f`, scanned OCI
`sha256:17d746ee4af707da6f7d577b26a71bfa9f348d1b3d5c257f3bc199c1acfc5608` and
extension pin `d9423db16e2bbe31bfb1dcc83c9a9441a18a6075`.
[Full CI 39162719045](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39162719045)
finished with 55 successful jobs, three failures and one skipped job. Four
installed delegation cells passed; both Kubernetes 1.35.0 cells and the required
aggregate failed. No retry/quarantine or passing full qualification is inferred.

| Keycloak | Kubernetes | Result | Assertions passed | Native phases recovered | Initial convergence (s) |
| --- | --- | --- | ---: | ---: | ---: |
| 26.7.5 | 1.35.0 | Incomplete | 31 | 0 | 397.810 |
| 26.7.5 | 1.36.2 | Complete | 88 | 4 | 115.489 |
| 26.7.5 | 1.37.0 | Complete | 88 | 4 | 217.218 |
| 26.8.0 | 1.35.0 | Incomplete | 31 | 0 | 402.960 |
| 26.8.0 | 1.36.2 | Complete | 88 | 4 | 184.246 |
| 26.8.0 | 1.37.0 | Complete | 88 | 4 | 160.289 |

Both failed cells first completed native initial provisioning within the unchanged
600-second budget and passed independent delegated resource/scope denials. Each
then exceeded the unchanged 180-second wait for a new applied resource-server
plan after an application generation change. The application was Ready; the
resource server reported `ReconcileFailed`. This differs from the older e29b3d5
initial `OwnershipConflict`; that older failure remains retained separately.
The four successful cells completed all 88 assertions and four native-phase
recoveries, including cleanup, expiry, replay refusal and measured withdrawal.

Failure-only native diagnostics contain booleans and counts: client UID/kind,
protocol, native ID, delegation owner/audience and authorization owner all matched;
native journals and grants remained present. These observations do not establish
the masked provider operation's failure cause or authorize ownership bypass.

Sanitized operator logs show repeated Kubernetes watch decode failures containing
an unexpected `H`. The fault proxy could append an HTTP 502 response to an
already-open JSON watch when its finite upstream read timed out. This independent
harness defect is reproduced and corrected in the follow-up source. Whether it
caused these two reconciliation deadlines requires corrected-source installed
qualification. No timeout, provider guard, permission or status acceptance was
relaxed. #71 remains open.

Only bounded public reports, failed wait summaries and the CI job snapshot are
retained here, with recursive SHA-256 hashes. Raw native representations, UIDs,
credentials, tokens and provider response bodies are not included.
