# Six accepted-write checkpoints across actual leader replacement

Installed runtime and final harness source: `5d5e3f7381d7215d29a1b2b43e113766e5b2da45`.
The [OCI summary](oci-summary.json) binds both scanned runtime platforms.
This packet is development qualification for selected parts of #96 and #110.

## Completed installed scenarios

| Real cell | Fixed checks | Completed checkpoints | Disposable cleanup |
| --- | --- | --- | --- |
| Kubernetes 1.37.0 / Keycloak 26.7.5 | 14 | 6 | pass |
| Kubernetes 1.37.0 / Keycloak 26.8.0 | 14 | 6 | pass |

The final [26.7.5 report](installed-keycloak-26.7.5.json) and
[26.8.0 report](installed-keycloak-26.8.0.json) each require three Secret rotation
boundaries, Observe client and role receipt recovery, and a signed Fleet
verification checkpoint. Each accepted-write response is lost externally, then
the exact lease-holder pod is deleted and confirmed absent before proxies are
released. Two serving replicas return with one observed leader matching a new
lease identity. No status reset, approval replacement or scaling to zero is used.

Each rotation has one native attempt and accepted rotation, one canonical Secret
PATCH, the same physical client and Secret identities, and recovered current
status from the same request. Acquisitions have one receipt write, unchanged
native semantics and credential, no Secret/finalizer acquisition, and zero
credential endpoint attempts from declaration through approval and recovery.
The verified plan creates one actual Kubernetes child and one native client;
the other tenant's physical client identity remains unchanged. Existing leakage
checks cover logs, Events, ConfigMaps, Hanko objects and decoded Hub payloads.

The executable contract and remaining limits are in
[transaction failover](../../../../transaction-failover.md).

## Source checks and scope binding

[Source results](source-results.json) record **343 Python tests**, chart/contract
checks, Actionlint and all repository hooks. The complete [security mutation
catalog](security-mutations.json) detects **53 mutations**, with every baseline
passing. This catalog ran at `07e9ce1`; the runner, catalog and Go source remain
unchanged by the subsequent Python probe/oracle corrections.

The [binary comparison](runtime-comparison.json) verifies that both final
operator binaries are byte-identical to `64e4890`. Runtime source, charts and
dependencies are unchanged. Its [earlier Go/API/Keycloak qualification](../../../recovery/2026-10-17/runtime-64e4890/README.md)
is referenced explicitly; those suites were not rerun as new-source results.

The [cold-cache experiment](cold-compilation.json) compiles the selected race
package in 49.807 seconds, then passes the first baseline and detects its mutant.
The [earlier CI timeout](previous-ci-mutation-timeout.json) remains a failure.
Cold compilation is a possible contributor, not a reproduced root cause. Separate
compilation never counts as a mutation detection; assertion and overall CI job
caps remain unchanged. Full-catalog preparation compiles eight packages without
executing tests before the required baseline/mutation assertions.

The signed CI tooling follow-up `ce09e3c` installs pinned ORAS in both scale
dispatch paths, using the repository's Go version and the exact directory passed
to the fixtures. The [earlier CI setup failure](previous-ci-scale-tool-failure.json)
has zero samples and checks: image mirroring failed before provider setup because
ORAS was absent. It is not a load measurement. A [fresh pinned installation](ci-tool-installation.json)
successfully reads this scanned multiarchitecture index locally. Linux CI
execution remains pending. The installed harnesses and operator binaries are
unchanged by this workflow/test/documentation-only follow-up.

## Retained initial failures and provider permission boundary

The [initial 26.7.5 run](initial-incomplete-keycloak-26.7.5.json) completes three
rotation checkpoints, then fails an incorrect expectation of reader credential
denial. The [existing permissions contract](../../../../keycloak-permissions.md)
already documents that this pinned reader profile can read client secrets on
26.7.5, while the endpoint is denied on 26.8.0. Final reports retain the exact
version-specific outcome and actual denied client PUT. **Provider-level
credential-read separation on 26.7.5 is not qualified.** The separate zero-call
and no-leakage acquisition assertions remain mandatory on both versions.

The [initial 26.8.0 run](initial-incomplete-keycloak-26.8.0.json) completes five
checkpoints, then fails the original plan-count oracle. That oracle mixed
successful dry-run collection POSTs with writes and did not recognize creation
through Server-Side Apply PATCH. The final oracle counts only non-dry-run HTTP
201 creations, retains numeric plan counts and still requires one native create.
Neither initial incomplete report qualifies the full fixture.

## Still open

The other four Kubernetes/Keycloak cells await the opt-in CI matrix. Every other
journal, delegation apply, stale-lease split brain and replica clock skew remain
outside this fixture. Ongoing endurance runs are not completed 24-hour evidence.
No production HA, resource defaults, public release or protected merge is claimed.
