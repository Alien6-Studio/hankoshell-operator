# Qualification

Use Go tests for operator behavior and native Helm commands for the chart.
Python programs orchestrate installed scenarios and release verification; there
is no separate Python unit-test suite for these programs.

## Measured results and limits

These are the recorded measurements supporting the first public v1.0.0 release.
They describe synthetic workloads and specific injected faults; use them as a
starting point for sizing and validation in your own environment.

| Check | Observed result | What it establishes and where it stops |
| --- | --- | --- |
| [Endurance](https://github.com/Alien6-Studio/hankoshell-operator/issues/95) | 24 h continuous (86,401.967 s), 6,984 samples; largest sampling gap 16.144 s. | Current resource readiness with complete counters and continuity of both operator processes. This is one completed campaign. |
| Synthetic workload | 1,230 resources: 1,000 applications, 100 organizations, 100 roles, 20 resource servers and 10 realms. | All remained current and native client identities were preserved. Other mixes and larger populations need measurement. |
| Operator memory | 182 MiB peak sampled combined RSS across two replicas, with four workers per measured IAM controller. | Operator process memory for this workload; excludes Keycloak, database and cluster overhead. The combined peak does not establish each Pod's allocation. |
| Sustained request rates | 57.5 Kubernetes request starts/s and 49.9 provider requests/s. | Observed operator traffic, not maximum throughput or end-user transactions/s. Resource-server p95 latency is not established by this report. |
| Leader replacement | 20.794 s during the preceding application burst. | Recovery in that load/fault scenario, not a general recovery-time or zero-downtime guarantee. |
| Parallel bounded delegation | 1,440 completed cycles covering permission intersection, audience, expiry, replay protection and bounded depth, with independent resource-side checks. | Extension-backed delegation in the declared test configuration; stock Keycloak and arbitrary grant graphs are outside that result. |
| [Transaction recovery](https://github.com/Alien6-Studio/hankoshell-operator/issues/96) | Six accepted-write checkpoints pass across six Kubernetes/Keycloak cells. | Rotation, Secret projection, rotation commit, client acquisition, role acquisition and verified-plan application recover with one accepted native action or child creation per checkpoint. Other transaction boundaries remain unmeasured. |
| Live-leader API isolation | Five-minute isolation: natural lease expiry, leader replacement, zero old-leader provider writes and one accepted new-leader write. | Fencing for that caller-scoped fault. Arbitrary partitions, clock skew and universal production HA are not qualified. |

### Revisions and release verification

The endurance and parallel delegation measurements in
[#95](https://github.com/Alien6-Studio/hankoshell-operator/issues/95) use revision
`3cdeb319fe3aa3fce8bdb4620572076a93f4e12b`. Later mesh-recovery changes were
validated separately; they were not part of that 24-hour interval.
The [HA run](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/40017308258)
uses `ec8074067ee3244fdf63ad0b3b4b6751cfe6a418`: Kubernetes 1.35.0, 1.36.2 and
1.37.0 with Keycloak 26.7.5 and 26.8.0, including installed delegation HA.

The [v1.0.0 release run](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/40108065217)
qualifies source `2e58ca5696659803b26a39e92bafa0ada79c5d86`, with Keycloak
26.8.1 replacing 26.8.0 in the final matrix. The three Kubernetes versions remain
the same. [Independent publication verification](https://github.com/Alien6-Studio/hankoshell-operator/issues/107)
covers the AMD64/ARM64 image identity, signatures, all 17 release-asset hashes
and anonymous download of the digest-pinned chart. A scan records findings at
that time; it is not a promise that new vulnerabilities will never be reported.

Publication does not graduate the 17 experimental `v1alpha1` APIs. These results
do not establish general production sizing, cloud/CNI/CSI compatibility, portable
database recovery or cross-release rollback. Later revisions require their own
applicable qualification; historical measurements keep their original scope.

## Develop locally

Install the pinned tools described in [CONTRIBUTING](../CONTRIBUTING.md), then run:

```sh
make qualify                         # source checks, Helm, Go tests and coverage
make qualify PROFILE=unit            # Go tests and coverage
make qualify PROFILE=chart           # helm lint and helm template
make qualify PROFILE=kubernetes      # real API server and etcd
make qualify PROFILE=keycloak KEYCLOAK_VERSION=26.8.1
```

The supported versions and image/tool digests come from [versions.json](../versions.json).
The PR workflow runs the complete supported matrix. Main verifies its successful
source proof after integration; release reuses that proof and qualifies the final
image across every installed-image cell. Source proofs remain available for
30 days and OCI archives for seven days. If evidence expires, explicitly run
complete CI on the exact intended revision. Reports and JUnit files are CI
artifacts; local reports belong in `.tools/runs/`.

## Exercise an installed operator

Installed scenarios use a scanned immutable OCI archive, its matching evidence,
the full source revision and the pinned fixture tools. They create disposable
clusters. They do not use your current kubeconfig.

```sh
make qualify PROFILE=installed \
  OCI_ARCHIVE=/path/to/image.tar OCI_EVIDENCE=/path/to/evidence \
  DIGEST=sha256:... REVISION=<full-commit> \
  SYSTEM_OUTPUT=/path/to/fresh/system.json \
  KIND=/path/to/kind KUBECTL=/path/to/kubectl ORAS=/path/to/oras \
  OPENSSL=/path/to/openssl
```

Other profiles cover `workload`, `delegation`, `fleet`, `portable`,
`scale`, `recovery` and `transactions`. Use `make -n <target>` to inspect their
inputs. [Operator runbooks](operations-runbooks.md) explain recovery and cleanup.

The scale fixture creates a burst of 1,000 applications, exercises leader loss
and provider/API failures, and records convergence, request rates and memory.
The transaction fixture interrupts accepted writes and checks journal recovery.
A passing short scenario is evidence for its stated cell and faults only.

## Run endurance on a persistent cluster

Use a dedicated `hanko-qualification-*` namespace, its own Keycloak, two
candidate replicas and the declared synthetic load. Keep the existing installation
and credentials separate. Metrics require the fixture's mutual TLS identity.

`python3 -m tools.qualification.runners.cluster_job --help` renders the Job
from the reviewed fixture configuration and scanned OCI evidence. Apply the
manifest with `kubectl apply --server-side`; the source/corpus ConfigMap is too
large for kubectl's last-applied annotation.

The Job first establishes the load and exercises an actual leader loss. Once
all objects have current read-back readiness, it measures 24 continuous hours.
It reads its rotating projected service-account token on every API call.
Interrupted sampling, replaced processes or lost readiness invalidate the run;
failed Jobs do not resume an earlier interval.

Transient API/metrics GET failures have at most three attempts, each bounded by
five seconds. Retries and numeric transport diagnostics are recorded; the
45-second sampling limit still invalidates any longer gap. Writes and OAuth
token exchanges are never replayed automatically.

Progress, numeric samples and the final report remain on the Job's PVC under
`/evidence/campaign/`. Collect them before removing the dedicated namespace.
The report states its source/digest, actual scope and remaining HA limitations.
Do not treat a running Job or a completed setup as a completed soak.

## Packaging and historical upgrades

The API remains `v1alpha1` for both serving and storage. The **Package** workflow
packages the scanned image, digest-pinned chart, scan results and checksums. It
creates no product tag or public release. Its explicit `publisher_access` option
initializes the image by digest and catalog metadata for first-time publisher setup.

```sh
python3 -m tools.release.release_bundle --archive /path/to/image.tar \
  --evidence /path/to/evidence --digest sha256:... --revision <full-commit> \
  --output /fresh/delivery --helm /path/to/helm
```

The installed suite also captures its synthetic objects and schemas.
[v1.0.0](https://github.com/Alien6-Studio/hankoshell-operator/releases/tag/v1.0.0)
is the first public release. For subsequent deliveries, **Public predecessor
compatibility** needs the retained, privacy-reviewed corpus and authenticated
artifacts of the supported public predecessor before running upgrade/rollback
cells. `make cross-version-installed-test` runs one such cell locally. The initial
v1.0.0 corpus's `NoPublishedPredecessor` limitation does not qualify a later upgrade.

Endurance and HA/recovery are complete in #95 and #96 for their stated scope.
The initial publication completed final-candidate qualification and independent
publisher verification, tracked in
[#106](https://github.com/Alien6-Studio/hankoshell-operator/issues/106) and
[#107](https://github.com/Alien6-Studio/hankoshell-operator/issues/107).
Each subsequent delivery requires its own qualification and independent approval;
publication does not graduate the experimental API.
Machine-consumed contracts and retained synthetic proofs live under
[`tools/qualification/config/`](../tools/qualification/config/).
