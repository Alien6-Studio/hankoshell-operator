# Contributing

Use English for issues, pull requests, documentation, and commit messages.
Participation follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Keep a pull request focused and describe the problem, resulting behavior,
validation, and operational impact. Add a sign-off with `git commit -s`.

## Developer Certificate of Origin

Each contributor commit must carry a final `Signed-off-by: Name <email>` trailer
certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Use `git commit -s`; the trailer must match the commit's author name and email
(email comparison ignores case). Coauthor or maintainer trailers may accompany
the author's trailer. A sign-off is a contribution certification; the separate
protected-branch signature requirement authenticates the commit.

The required CI source gate checks every commit in the PR's base-to-head range,
including merge commits, with `scripts/check-dco.py`. It checks the actual PR
head, not GitHub's generated test merge. Missing or mismatched author sign-offs
fail with the affected commit SHAs. Correct contributor commits with
`git commit --amend -s` or a reviewed history rewrite; preserve other contributors'
sign-offs and signatures when updating their work.

Two narrow automation exceptions apply when the author-matching trailer is absent:
the canonical `dependabot[bot]` author authenticated as GitHub's Dependabot bot,
and commits made by the authenticated GitHub `web-flow` committer
(`GitHub <noreply@github.com>`). Both require GitHub API confirmation of the exact
commit SHA, author and committer, plus a `Verified` signature with reason `valid`.
Local bot names, committer names or signatures alone grant no exception. An API
failure or unverified signature rejects the exception. Other bots use sign-offs.

Before a protected squash merge, maintainers must edit the squash message to
retain the contribution sign-offs and include a trailer matching the resulting
squash author. GitHub can use the author's account display name rather than the
local Git name; check both the resulting name and email. The web-flow exception
allows the generated signed commit through automated checks; it does not remove
this maintainer squash-message rule. After merging, verify the squash commit's
sign-offs and GitHub `Verified` signature before resolving the issue.

To reproduce the PR check locally after fetching both full commit SHAs:

```sh
python3 scripts/check-dco.py --base "$base_sha" --head "$head_sha" \
  --repository Alien6-Studio/hankoshell-operator
```

Ordinary signed-off commits require only Git. Automation exceptions also require
the authenticated `gh` CLI with read access to the repository.

## Architecture decisions

The [decisions index](docs/architecture/decisions/README.md) records the accepted
architecture referenced by code and configuration. Follow its template and
numbering rule when documenting a decision, and keep links to enforcing code and
tests current. Run `python3 scripts/check-adr-references.py` before pushing changes
to Go, YAML or Markdown. CI rejects unresolved references and orphan records.

## Validation and release workflow

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
