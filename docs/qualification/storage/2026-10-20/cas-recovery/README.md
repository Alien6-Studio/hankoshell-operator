# Native storage migration conflict recovery

The completed [main CI run](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39412612756)
failed during the Kubernetes 1.36.2 `resume_rewrite` stage. Its
[original report](main-ci-1.36.2-opaque-failure.json) retained no CLI refusal code;
the precise cause of that original failure is therefore unknown.

A deterministic disposable-cluster diagnostic reproduced a real defect in the
same stage: another writer's metadata-only CRD PUT causes the migration's stale
resourceVersion PUT to return HTTP 409. The original CLI stopped with
`ConcurrentModification`. The [baseline native report](before-native-cas-1.36.2.json),
[fixed-code diagnostic](before-refusal.json) and
[actual-conflict witness](before-native-conflict.json) retain that result.
The diagnostic injected its external wrapper in addition to the original harness;
this does not establish that the opaque CI failure had the same cause.

The CLI now skips unchanged CRD writes and retries only explicit 409 responses,
at most four times. Every retry rechecks identity, schema/generation, storage,
quiescence and complete object meaning; a status commit also re-observes native
migration success. Unknown write outcomes and changed authority still refuse.
Completed/resumed journals never substitute for new native migration proof.

The permanent fixture performs real intervening metadata writes in both forward
and reverse migrations. Its first version reused one annotation value, which
could become a no-op on rollback; the
[incomplete first result](first-harness-reverse-conflict-not-proven.json) remains
retained. The corrected injection changes that value with the target version and
requires an actual 409 with unchanged CRD generation in both directions.

Final reports retain physical etcd encoding, four process interruptions,
16 successful native migrations, preserved object meaning/UID/managedFields,
two actual conflicts and complete cleanup. This is experimental local storage
qualification, without provider calls or a public-release upgrade claim.

| Kubernetes | Native report |
| --- | --- |
| 1.35.0 | [16 migrations, both conflicts](native-1.35.0.json) |
| 1.36.2 | [16 migrations, both conflicts](native-1.36.2.json) |
| 1.37.0 | [16 migrations, both conflicts](native-1.37.0.json) |

An additional preflight regression found that the old single-name workload
selector missed the chart's default `hanko-operator` name. A stopped canonical
deployment could therefore hide a live legacy/custom writer. The corrected guard
scans complete paginated inventories and recognizes both names and the fixed
Pod/template marker. Unit negatives cover mixed deployments, terminating Pods
and a live writer on a later page. The
[native guard witness](native-quiescence-1.35.0.json) passes all six checks without
starting an operator or contacting a provider. The native CAS matrix above precedes this
separate guard correction; component identities retain that boundary. The current
batch still requires its final protected CI, without treating earlier reports as
an exact-revision qualification.

The [source identities](source-identities.json) retain original report checksums.
Public JSON views use canonical whitespace and rename the contract content-hash
field to `contract_sha256`, avoiding its misclassification as an API credential
by secret scanning. Measurement values and failures are unchanged. Source
component hashes distinguish the CAS matrix from the final guard/diagnostic code.

The [runbook](../../../../storage-migration.md) describes operational ordering,
approval and rollback. A passing targeted fixture does not replace the current
batch's protected CI.
