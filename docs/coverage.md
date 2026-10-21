# Go coverage regression gates

`make coverage` runs the unit suite once with `-race -count=1 -covermode=atomic`,
then checks the resulting profile against
[`tools/qualification/config/coverage-floors.json`](../tools/qualification/config/coverage-floors.json).
`make check` includes this gate. CI runs it explicitly in the required source job
after unit tests, without changing the other qualification gates.

The profile, `go tool cover -func` output, machine-readable counts and Markdown
summary are stored under `.tools/runs/tests/unit/` and uploaded with the JUnit
results, including on failure. Package and named-function percentages also appear
in the Actions step summary. Existing results are removed before a new test run;
a missing profile cannot reuse a previous success.

## Baseline and thresholds

The [committed baseline](../tools/qualification/config/coverage-baseline.json) was measured from
protected `main` commit `a10f2351fedf49ccfbabe200725d2a814c2b0a07` on Darwin arm64
with Go 1.27.2. It records the exact command, statement counts, selected function
percentages and SHA-256 digests of the original profile and function report. The
source was extracted with `git archive` into a disposable build directory and
removed after measurement; no branch or Git checkout is needed to reproduce it.

The global baseline is 12,136 / 19,858 statements (61.1139%). Ordinary package
and global floors subtract one percentage point and round down to one decimal.
The committed global floor is 60.1%. Security packages `httpsecurity`,
`imagevalidator`, `workloadtrust`, `workloadauth`, `hub` and `selfupdate` retain
that baseline floor or 85%, whichever is higher. The organization ownership
package has new direct tests and a 100% floor. Sixteen named security functions
have individual 90–100% floors, including immutable image approval, HMAC integrity,
TLS origin binding, JSON validation and plan revalidation.

Coverage is statement-weighted: large packages do not get the same weight as
small packages, and package percentages are never averaged. Global/package
comparisons use exact covered/total counts. Function comparisons use the
one-decimal percentages reported by `go tool cover -func`. Function identities
are source path plus name, so moving line numbers does not reset a floor; a
missing or ambiguous name fails until explicitly reviewed.

Unit coverage is measured within each package, without `-coverpkg` aggregation
from callers' tests. Generated API code and the command helper retain their
measured zero floors. `internal/version` contains only a variable and contributes
no executable statements. These are explicit limits of this measurement. Envtest
runs also produce atomic profiles in their Kubernetes-version artifact directories;
their coverage is not merged into the unit floor. Real-Keycloak qualification
retains its existing scope and is not coverage-floored here.

Coverage measures statement execution; it does not establish assertion quality,
security correctness or installed-system qualification. Existing behavioral,
adversarial, race, provider and installed tests remain required.

## Reviewing a change

Run `make coverage`, inspect `.tools/runs/tests/unit/coverage-summary.md`, and
add behavioral tests for the changed contract. A low result reports the package
or exact security function and its required percentage. A new package requires an
explicit floor; removing a package or renaming a floored function requires an
intentional policy edit. Malformed, duplicate or foreign profile data fails the
check instead of shrinking the denominator silently.

Change floors only through a reviewed source change with the measurement and
reason. Prefer raising a floor after adding useful tests; do not regenerate floors
automatically from a failing run. Keep the historical baseline intact when updating
thresholds. To reproduce it, extract its recorded revision and run the recorded
`go test` command followed by `go tool cover -func=coverage.out` inside that source
snapshot. A new baseline needs its own explicit revision, environment and evidence.

The operational telemetry/TLS leaf added on the development branch has an explicit
89.5% package floor (measured 104/116 statements, 89.66%, on signed revision
`019b094df300137abf0cd729e7007f0976cd44a1`). This adds a reviewed package entry;
the historical baseline and all existing floors remain intact. Actual TLS refusals,
URI authorization, trust reload and secret redaction also have mutation assertions.
