# Local storage recovery and CI corrections

The native fixture completed 48 fresh migrations and twelve actual
CLI interruptions across Kubernetes 1.35.0, 1.36.2 and 1.37.0. Each cell exercised
alpha → beta → alpha, preserved object meaning and authority metadata, verified
physical etcd encoding, resumed the same approved plans after rewrite and commit
interruptions, and checked the live chart storage guard. Disposable cleanup was
independently checked after each final cell.

| Kubernetes | Report | Harness source |
| --- | --- | --- |
| 1.35.0 | [Native result](storage-1.35.0.json) | `0d2b14348bbc739e4fed8b0563b6bca1d888ac4a` |
| 1.36.2 | [Native result](storage-1.36.2.json) | `067ef1bf6e845fc9e01007144a0f3b8549cf60c5` |
| 1.37.0 | [Native result](storage-1.37.0.json) | `067ef1bf6e845fc9e01007144a0f3b8549cf60c5` |

The [source manifest](source-manifest.json) binds the actual harness variants,
production CLI, API decision, chart, pins and diagnostic tests. The later variant
changes failure-report retention and cleanup. AST-segment hashes confirm that
command execution, process interruption and native qualification bodies are
unchanged. These runs do not claim one final full-CI revision: the new required
three-version CI job must qualify its own head.

The [CI run](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39282266290)
failed because the beta API package lacked a coverage floor and the tagged SSA
tests used a deprecated controller-runtime API. Authentik artifact upload then
failed because its fixture had been skipped. The corrections add the measured
41.7% beta floor without lowering existing thresholds, use supported Apply calls
and retain provider outputs only when that fixture started.

On the frozen source `caf9b67d68a149cc1be24f617f43dc0fc18bd8e6`, local validation
passed 2,772 race-enabled Go unit cases and all coverage floors. The API
fixture passed 387 Kubernetes 1.37 cases; tagged integration lint reported zero
issues. The complete hooks passed 420 Python tests, formatting, vet, architecture
and staged secret checks. [Validation metadata](local-validation.json) records
counts and hashes; [attempt accounting](attempt-accounting.json) retains excluded
incomplete runs, including the earlier cleanup failure and source-changing test
attempt. Neither is counted as qualification.

Typed IAM refusal tests cover wrapped HTTP status errors, cancellation, precedence,
text spoofing, preservation of prior application evidence and private-message
exclusion. These tests and storage fixtures use synthetic resources. They do not
qualify real-provider upgrades, public predecessor compatibility, independently
approved finalizer release or stable API graduation. #92 and #103 remain open.
The [separate delegation diagnostic](../../../delegation/2026-10-19/runtime-643f607/README.md)
uses an older scanned runtime and leaves #71 intermittence unresolved.
