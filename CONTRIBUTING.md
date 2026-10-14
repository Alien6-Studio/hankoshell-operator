# Contributing

Use English for issues, pull requests, documentation, and commit messages.
Participation follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Keep a pull request focused and describe the problem, resulting behavior,
validation, and operational impact. Add a sign-off with `git commit -s`.

Run `make check arch lint generated-check vuln` with the pinned tools.
`make check` includes the [coverage regression gate](docs/coverage.md); use
`make coverage` for the unit suite and its reviewed package/security-function
floors. Update thresholds explicitly with supporting measurements, never by
automatically accepting a failing run as the new baseline.
Run `python3 -m unittest discover -s scripts -p 'test_*.py'`, both real Keycloak
versions and the three Kubernetes fixtures listed in CI. The final OCI scan
and [nonpublishing release rehearsal](docs/secure-deployment.md#release-rehearsal-and-publication)
are required CI checks; a source-only test run is not release qualification.
The installed-system check combines the chart, scanned OCI image, real kind
Kubernetes and HTTPS Keycloak. The release rehearsal also tests interrupted
publication/retry against a disposable registry and a GitHub storage fixture.
`make lint` installs and verifies golangci-lint in the ignored `.tools` directory.
Behavior changes need meaningful regression tests. Changes to CRDs, provider
ownership, deletion, adoption, or authentication need migration and rollback
instructions. Use synthetic fixtures and keep credentials and tenant data out
of the repository.

Target public release is 0.1.0; active technical metadata is `0.1.0-dev.0`
in initial development. No public release has been published yet. The `v1alpha1`
APIs remain experimental. Keep chart/build/rehearsal metadata, prerelease status
and curated changelog notes consistent.

Changes use short-lived PR branches and protected squash merges signed by GitHub.
The initial root must be signed and GitHub Verified. Engineering Phases 1–10
lead to the first public 0.1.0; use milestones, issues/RFCs, PRs, commits and CI.
Do not create SemVer development/phase tags or alternative checkpoint tags.
Production publication is blocked until reviewed source metadata explicitly
prepares a stable candidate. Its future signed annotated tag is `v0.1.0`, bound
to the exact qualified protected-main commit. Full qualification, signature and
ancestry checks, Sigstore artifact signatures and native Continuum Attest
verification remain required. A later 1.0 decision follows actual public use,
proven migrations/conversions and an explicit backward-compatibility policy;
Phase 10 qualifies the initial public contract without promising that graduation.

Contributions are licensed under Apache-2.0. Maintainers review changes before
merge. Report security issues using [SECURITY.md](SECURITY.md).
