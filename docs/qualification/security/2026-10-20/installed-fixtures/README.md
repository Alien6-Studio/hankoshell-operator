# Installed fixture corrections for #99

[CI 39330554264](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39330554264)
passed 54 jobs. Six installed cells and their aggregate gate failed; they are
retained as failures. CodeQL, the source/API/provider/security gates, scanned OCI,
installed system, release rehearsal and delegation scenarios passed. This packet
explains the fixture corrections, not acceptance of that failed run.

| Cause | Correction and regression |
| --- | --- |
| The positive Deployment probe ran after checking only Secret policy propagation | Readiness now requires approved CREATE and unrelated-name refusal for both resources. A stale or missing policy cannot count as ready. |
| Acquisition counted credential reads across all clients after handoff | The private fault proxy counts attempts per endpoint, including blocked reads. The assertion uses the exact Observe target; unrelated activity cannot hide a target read or cause a false failure. Missing observations fail closed. |
| A future forced rotation combined two distinct triggers | An unknown initial rotation time makes the interval immediately due. A force two seconds later requests another legitimate rotation. The fixture now selects an already-due force strictly after the prior status second; its original same-request, exact-status and single-native-operation assertions remain. |

The [diagnostic witness](validation.json) retains the reproduced timing: the first
request started before the future force and another request started afterwards.
The old repeated scenario failed at its second client; all eight corrected cycles
passed. A full six-checkpoint transaction, target-scoped acquisition checks and
natural live-holder API partition passed on Keycloak 26.7.5 / Kubernetes 1.37.0.
Local validation passed 459 Python tests, preflight, tagged lint and the Go
rotation-policy regression under the race detector. No deadline was increased, assertion removed,
failed test automatically retried or test quarantined.

The local diagnostics use the already scanned `d938d9b` runtime with the repaired
dirty Python harness. They do not qualify the next compiled image. The original
[source audit](../../2026-10-19/bounded-contract/README.md) keeps its original
campaign identities; this packet identifies the fixture follow-up separately.
Final acceptance still requires every existing gate on the exact new image,
protected squash, GitHub Verified signature and a Resolution on #99. No tag,
release, registry publication or production approval is created.
