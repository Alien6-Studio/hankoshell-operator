# Qualification

Use Go tests for operator behavior and native Helm commands for the chart.
Python programs orchestrate installed scenarios and release verification; there
is no separate Python unit-test suite for these programs.

## Develop locally

Install the pinned tools described in [CONTRIBUTING](../CONTRIBUTING.md), then run:

```sh
make qualify                         # source checks, Helm, Go tests and coverage
make qualify PROFILE=unit            # Go tests and coverage
make qualify PROFILE=chart           # helm lint and helm template
make qualify PROFILE=kubernetes      # real API server and etcd
make qualify PROFILE=keycloak KEYCLOAK_VERSION=26.8.0
```

The supported versions and image/tool digests come from [versions.json](../versions.json).
The PR workflow runs the complete supported matrix. Reports and JUnit files are
CI artifacts; local reports belong in `.tools/runs/`.

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

Other profiles cover `workload`, `delegation`, `fleet`, `portable`, `storage`,
`scale`, `recovery` and `transactions`. Use `make -n <target>` to inspect their
inputs. [Operator runbooks](operations-runbooks.md) explain recovery and cleanup;
[storage migration](storage-migration.md) covers CRD upgrades and rollback.

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

Progress, numeric samples and the final report remain on the Job's PVC under
`/evidence/campaign/`. Collect them before removing the dedicated namespace.
The report states its source/digest, actual scope and remaining HA limitations.
Do not treat a running Job or a completed setup as a completed soak.

## RC1 and historical upgrades

The current candidate is `1.0.0-rc.1`. APIs remain experimental, including served
beta candidates; storage remains `v1alpha1`. The **Release candidate** workflow
packages the scanned image, digest-pinned chart, scan results and checksums. It
creates no stable tag or public release.

```sh
python3 -m tools.release.release_candidate --archive /path/to/image.tar \
  --evidence /path/to/evidence --digest sha256:... --revision <full-commit> \
  --output /fresh/candidate --helm /path/to/helm
```

The installed suite also captures its synthetic objects and schemas. After an
actual public release and privacy review, **Public predecessor compatibility**
runs upgrade/rollback cells from that authentic corpus and signed artifacts.
`make cross-version-installed-test` runs one such cell locally. With no public
predecessor there is no historical upgrade guarantee to claim.

Stable delivery still requires completed endurance/HA, actual compatibility
proofs, ratification and independent publisher trust. These are tracked in
[#106](https://github.com/Alien6-Studio/hankoshell-operator/issues/106) and
[#107](https://github.com/Alien6-Studio/hankoshell-operator/issues/107).
Historical campaign reports remain in Git history and their linked CI runs;
current machine-consumed contracts and retained proofs live under
[`tools/qualification/config/`](../tools/qualification/config/).
