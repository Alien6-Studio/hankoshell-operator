# Contributing

Use English for issues, pull requests, documentation, and commit messages.
Participation follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Keep a pull request focused and describe the problem, resulting behavior,
validation, and operational impact. Add a sign-off with `git commit -s`.

Run `make check arch lint generated-check vuln` with the pinned tools.
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

Version 0.1.0 is a normal SemVer release in initial development, not a beta or
SemVer prerelease. The `v1alpha1` APIs remain experimental and may change across
minor versions before 1.0. Keep chart, release metadata and curated changelog
notes consistent with that distinction.

Changes use short-lived PR branches and protected squash merges, signed by GitHub.
The initial root may be unsigned. Release tags may be lightweight or annotated;
Git signatures are not delivery prerequisites. After `v0.1.0` is created, never
rewrite its source history or move/delete the tag. The release workflow requires
full qualification, Sigstore artifact signatures and Continuum Attest verification.

Contributions are licensed under Apache-2.0. Maintainers review changes before
merge. Report security issues using [SECURITY.md](SECURITY.md).
