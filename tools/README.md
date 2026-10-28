# Tooling

`qualification/` contains the shared qualification framework, usable locally and
from CI through `make qualify`. Go tests stay beside the packages they exercise.
The operator runtime depends on none of these Python or shell programs.

| Location | Purpose |
| --- | --- |
| `qualification/checks/` | Coverage, licenses, API/security compatibility and release contracts |
| `qualification/runners/` | Go/JUnit, provider, fuzz and mutation runners |
| `qualification/scenarios/` | Installed reconciliation, migration, recovery and endurance campaigns |
| `qualification/fixtures/` | Disposable providers, pod probes and Go helpers |
| `qualification/lib/`, `qualification/reporting/` | Shared diagnostics, privacy and measurements |
| `qualification/config/` | Floors, shards, contracts and reviewed reference proofs |
| `bootstrap/`, `versions.py` | Pinned build tools and version manifest |
| `release/` | OCI scanning, signing, packaging and publication |
| `operations/` | Administrator adoption and recovery commands |
| `olm/` | Go generator for chart-derived OperatorHub bundles and administrator preparation |
| [`.github/scripts/`](../.github/scripts/) | GitHub DCO/protection checks and run-history reporting |

## Run

Use the repository root and the prerequisites in
[CONTRIBUTING.md](../CONTRIBUTING.md). Native `go test ./...`, `go vet ./...`,
`helm lint` and `helm template` work directly. Make adds reports, coverage and
installed qualification:

```sh
make qualification-help
make qualify                       # local source, Helm, Go/race and coverage
make qualify PROFILE=chart         # Helm only; no cluster
make qualify PROFILE=keycloak KEYCLOAK_VERSION=26.8.1
python3 -m tools.bootstrap.install helm kind kubectl --directory .tools/bin
```

Installed profiles are `installed`, `workload`, `delegation`, `fleet`, `portable`,
`scale`, `recovery` and `transactions`. They require a scanned immutable
image archive, matching evidence, digest and source revision, and a fresh output
path. Their normal fixtures create disposable local clusters. See the
[installation guide](../docs/secure-deployment.md),
[scale and soak](../docs/qualification.md) for inputs and limits.

The persistent runner is available through
`python3 -m tools.qualification.runners.cluster_job --help`. It renders a Job
for an explicitly prepared isolated fixture; it never deploys it automatically.
Operational commands have their own help, for example
`python3 -m tools.operations.claim_existing --help`.

## Local data

`.tools/` is ignored: `bin/` holds executables, `cache/` dependencies, `venv/` the
Python environment and `runs/` private reports. Go/JUnit reports default to
`.tools/runs/tests/`; `TEST_REPORT_DIR` overrides it. Kubeconfigs, real cluster
identifiers, endpoints, credentials and raw reports must stay out of Git.
Reviewed public reference proofs use synthetic fixtures and sanitized data.

CI keeps its complete version matrix. A local run does not establish successful
endurance, public predecessor compatibility or approval to publish a release.
