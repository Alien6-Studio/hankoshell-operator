# Contributing

Qualification suites, tooling layout and local artifacts: [tools/README.md](tools/README.md).

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
including merge commits, with `.github/scripts/check_dco.py`. It checks the actual PR
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
sign-offs and GitHub `Verified` signature as part of integration verification.

To reproduce the PR check locally after fetching both full commit SHAs:

```sh
python3 .github/scripts/check_dco.py --base "$base_sha" --head "$head_sha" \
  --repository Alien6-Studio/hankoshell-operator
```

Ordinary signed-off commits require only Git. Automation exceptions also require
the authenticated `gh` CLI with read access to the repository.

## Optional local pre-commit checks

Use Python 3.12, the reviewed Go toolchain and the tools installed by
`make install-tools`. Activate a project Python environment and install
`tools/requirements.txt` before running the hooks:

```sh
python3.12 -m venv .tools/venv
. .tools/venv/bin/activate
python -m pip install -r tools/requirements.txt
make install-tools
make hooks-check
python3 .tools/bin/hooks/pre-commit.pyz install
```

The final command optionally installs a client-side Git hook. If you use a
shared `core.hooksPath`, preserve it and run `make hooks-check` manually or call
the pinned runner from your existing hook. No shared Git configuration needs
to change. CI remains authoritative and runs the same `--all-files` hook set
in the source job and on development pushes.

`.pre-commit-config.yaml` pins upstream hooks to an immutable commit SHA.
`versions.json` pins the pre-commit zipapp and Gitleaks release archives by
SHA-256; `make hook-tools` verifies cached downloads before using them.
The hooks check large files, raw private-key markers, merge conflicts,
YAML/TOML/JSON syntax, final newlines, Go formatting, architecture and staged
secrets. Helm templates are excluded only from plain YAML parsing and remain
covered by the chart gate. Synthetic private-key markers are assembled in
tests so every source file remains eligible for raw-key detection.

`go vet ./...` checks the module when Go files or dependencies change.
Full qualification runs the Make and CI gates.
Gitleaks checks the staged diff locally; the existing source-job directory scan
also checks the complete checkout in CI. CI stores upstream hook repositories
in the runner's temporary directory, so their own secret-detection fixtures are
not confused with project source. `PRE_COMMIT_HOME` can override the local cache.

Review hook updates weekly alongside Dependabot updates. Use
`python3 .tools/bin/hooks/pre-commit.pyz autoupdate --freeze`, review the exact
upstream commit diff and retain the frozen SHA, then run `make hooks-check`.
Update runner/Gitleaks versions and official release
SHA-256 digests in `versions.json`, run `python3 -m tools.versions sync`,
and rerun the gates. Do not replace a SHA with a floating branch or tag.

## Architecture decisions

The [decisions index](docs/architecture/decisions/README.md) records the accepted
architecture referenced by code and configuration. Follow its template and
numbering rule when documenting a decision, and keep links to enforcing code and
tests current. Review affected links when changing or renumbering a decision.

## Validation and release workflow

Run `make check arch lint generated-check vuln` with the pinned tools.
`make check` includes the [coverage regression gate](docs/coverage.md); use
`make coverage` for the unit suite and its reviewed package/security-function
floors. Update thresholds explicitly with supporting measurements, never by
automatically accepting a failing run as the new baseline.
Run both real Keycloak versions and the three Kubernetes fixtures listed in CI. The final OCI scan
and [nonpublishing release rehearsal](docs/secure-deployment.md#release-rehearsal-and-publication)
are required CI checks; a source-only test run is not release qualification.
The installed-system check combines the chart, scanned OCI image, real kind
Kubernetes and HTTPS Keycloak. The release rehearsal also tests interrupted
publication/retry against a disposable registry and a GitHub storage fixture.
`make lint` installs and verifies golangci-lint in the ignored `.tools` directory.
Behavior changes need meaningful regression tests. Changes to CRDs, provider
ownership, deletion, adoption, or authentication need migration and rollback
instructions. Use synthetic fixtures. Keep live cluster identifiers, endpoints,
kubeconfigs, credentials, tenant data and raw qualification reports out of the
repository; local evidence belongs in the ignored `.tools/` directory.

Follow the [API conversion and rollback policy](docs/api-migration-policy.md).
The [development support inventory](docs/api-support.md) covers every resource
and spec/status field group; update it explicitly when those groups change.
Run `make preflight` and the relevant Go conformance/admission tests after schema changes.

Develop related issues as one bounded batch. During implementation, run preflight
and meaningful targeted regression tests, and continue independent work while CI
runs. Run the full qualification matrix on the final batch revision before
integration; it remains mandatory on every pull request. After squash merge,
main verifies the successful qualification proof against the exact integrated
Git tree instead of repeating the matrix. Release reuses the source proof and
qualifies the final scanned image across every installed-image cell before
publication. See [ADR-009](docs/architecture/decisions/ADR-009-full-pull-request-qualification.md).

Close an implementation issue when its implementation is complete and pushed to
the development branch. Add a Resolution comment with the exact commit, delivered
scope, validation already available and any remaining integration/qualification
evidence. Do not wait for a protected-main merge to record implementation delivery.
This push-based tracking rule supersedes older issue text that required waiting
for a protected squash before closure. Keep issues with unfinished implementation
open and identify the missing work. Issue closure does not attest that a merge,
complete qualification, public compatibility decision or publication occurred;
those retain their own gates and evidence requirements.

Run `make licenses` after dependency updates. License classification and shipped
notices use the union of Linux AMD64 and ARM64 dependency graphs with CGO disabled,
matching the operator and embedded cosign builds. Both platform graphs are checked
against the same license/source policy, including operator test dependencies.
Generation uses these explicit targets on every developer host; commit both
`THIRD_PARTY_NOTICES` files after reviewing the resulting inventory and texts.

The `v1alpha1` APIs remain experimental and in initial development.
Keep source, chart and build versions aligned
with `versions.json`.

Changes use protected, signed squash merges. Publication requires the complete
qualification, independent release approval and a signed annotated `v1.0.0` tag
on protected main. Production publication stays blocked while the manifest status
is `development`; there is no CLI or environment override.

Contributions are licensed under Apache-2.0. Maintainers review changes before
merge. Report security issues using [SECURITY.md](SECURITY.md).
