# Development and qualification tooling

The operator runtime is Go (`api/`, `cmd/`, `internal/`). Python and shell here
prepare builds, exercise installations and check release evidence. They are not
runtime dependencies and are not shipped inside the Helm chart.

## Layout

| Location | Purpose |
| --- | --- |
| `qualification/checks/` | API, compatibility, security and operational contracts |
| `qualification/runners/` | Go/JUnit, Keycloak, fuzz and mutation runners |
| `qualification/scenarios/` | Installed operator, migration, recovery, scale and HA campaigns |
| `qualification/fixtures/` | Disposable provider servers, pod probes and Go test helpers |
| `qualification/reporting/` | Test history, flaky-test tracking and scheduled-run reports |
| `qualification/lib/` | Shared evidence privacy, diagnostics and qualification helpers |
| `qualification/config/` | Reviewed coverage floors, test shards and fuzz inventory |
| `release/` | OCI scanning, signing, packaging and publication |
| `operations/` | Administrator adoption, storage migration and finalizer recovery tools |
| `bootstrap/`, `quality/`, `versions.py` | Pinned tool installers, contributor checks and version manifest reader |
| `../tests/tooling/`, `../tests/chart/` | Tooling unit tests and render/package checks |

## Run a suite

Use the repository root, Python 3.12+ and the pinned dependencies/tools described
in [CONTRIBUTING.md](../CONTRIBUTING.md). Existing Make targets remain available.

```sh
make qualification-help
make qualify                         # local source, chart, Go tests and coverage
make qualify PROFILE=chart           # render and package checks; no cluster
make qualify PROFILE=keycloak KEYCLOAK_VERSION=26.8.0
make tooling-test                    # unit tests of this tooling
```

`source` runs contracts, tooling tests, generated-file checks, chart checks,
architecture and lint. `unit` runs Go unit/race tests and coverage. `kubernetes`
runs the real API-server suite. `extension` qualifies the pinned Keycloak SPI.
The `local` default combines source and unit checks; it does not replace the CI
version matrix or installed qualification.

Installed profiles are `installed`, `workload`, `delegation`, `fleet`, `portable`,
`storage`, `scale`, `recovery` and `transactions`. They call the existing reviewed
harnesses, with their existing required inputs and acceptance limits. They create
disposable local clusters; they do not select the current Scaleway context.

For example, the installed smoke suite requires the already scanned immutable
archive and matching evidence, source revision and digest:

```sh
make qualify PROFILE=installed \
  OCI_ARCHIVE=/path/to/image.tar OCI_EVIDENCE=/path/to/evidence \
  DIGEST=sha256:... REVISION=<full-commit> \
  SYSTEM_OUTPUT=/path/to/fresh/system.json \
  KIND=/path/to/kind KUBECTL=/path/to/kubectl ORAS=/path/to/oras \
  OPENSSL=/path/to/openssl
```

See [secure deployment](../docs/secure-deployment.md),
[scale and soak](../docs/scale-and-soak.md) and
[storage migration](../docs/storage-migration.md) for exact campaign inputs.
To inspect a tool directly, use its package entry point, for example
`python3 -m tools.operations.storage_migration --help`.

## Local data and evidence

`.tools/` is ignored: `bin/` holds executables, `cache/` reusable dependencies,
`venv/` the Python environment, `runs/` current reports and `archive/` older work.
Go/JUnit reports default to `.tools/runs/tests/`; `TEST_REPORT_DIR` overrides it.
Installed campaigns retain their fresh-output requirement and immutable image
checks. Keep private native objects, kubeconfigs and credentials out of Git.
Only sanitized, explicitly scoped evidence belongs in `docs/qualification/`.
A failed or interrupted run remains a failure; a local suite never implies a
successful 24-hour soak or permission to publish a stable release.

`system-test` also captures its synthetic objects in `system-test.corpus.json`.
After a genuine public release and privacy review, **Public predecessor
compatibility** runs the six upgrade/rollback cells from that corpus and signed
artifacts. `make cross-version-installed-test` runs one cell locally; its inputs
are listed in the target. No public predecessor means no historical guarantee.

For a prepared isolated cluster fixture,
`python3 -m tools.qualification.runners.cluster_job --help` renders the persistent load,
leader-loss and 24-hour measurement Job. Apply it with server-side apply; the
corpus is too large for kubectl's last-applied annotation. Progress and results
stay on its PVC, and failed campaigns never resume their measured interval.
