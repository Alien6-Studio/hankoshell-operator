# Kubernetes and Keycloak qualification/support window

This repository policy is active for **initial development qualification**.
It does not publish a release or grant stable API compatibility. The proposed
public rules in [compatibility-policy.md](compatibility-policy.md) await #87's
post-publication community review. Machine rules live in
[compatibility-policy.json](compatibility-policy.json); exact versions and immutable
fixture checksums live only in [versions.json](../versions.json).

<!-- support-window:start -->
| Component | Exact qualification versions | Default |
| --- | --- | --- |
| kubernetes | `1.35.0`, `1.36.2`, `1.37.0` | `1.37.0` |
| keycloak | `26.7.5`, `26.8.0` | `26.8.0` |
<!-- support-window:end -->

## Window rules

Qualify three consecutive Kubernetes minors and two consecutive Keycloak minors,
with one reviewed exact patch per minor and the newest qualified version as default.
Every exact version needs its existing immutable image/node/envtest fixture pins.
The chart's Kubernetes range advertises those minors, not evidence for every patch,
managed distribution, CNI/CSI or cloud provider. Native provider semantics and
version-specific restrictions remain explicit. Authentik is an opt-in experiment
and is not added to this supported Keycloak window by these rules.

Qualification of a historical version is not a promise that upstream still fixes
it. Production eligibility also requires a fresh upstream maintenance/EOL review;
this project never extends upstream support, including a cloud vendor's extended
support offering. Review the primary [Kubernetes release](https://kubernetes.io/releases/)
and [patch schedules](https://kubernetes.io/releases/patch-releases/) and the
[Keycloak release announcements](https://www.keycloak.org/blog/) for the specific
community/vendor distribution. We make no unverified claim that both qualified
Keycloak minors receive upstream security backports.

Review released security patches within 14 days. A replaced qualified patch gets
at most 30 days of migration grace, bounded by upstream EOL and security urgency.
This is a maintenance target, not permission to run a known vulnerable patch or a
contractual SLA. Weekly qualification is a regression check, not a patch adoption
proof. An urgent security release can shorten grace with an advisory and explicit
migration/rollback limitations. Before public support is advertised, the release
review must record upstream support eligibility and exact qualified artifacts.

## One reviewed change

1. Inspect the bounded official upstream release catalog/review packet. Reject
   prereleases, drafts, future dates, major/minor surprises and unsupported upstream
   branches. Review patch notes, native semantics and security urgency.
2. In the same reviewed PR, edit `versions.json` and supply actual reviewed image
   digests, envtest checksums and node fixtures. Never copy checksums from a proposal:
   proposals deliberately contain no fabricated fixture pins.
3. Run `python3 -m tools.versions sync`, then `python3 -m tools.versions check`.
   This updates CI matrices, chart metadata and generated tables in README,
   SECURITY, chart README, this policy and the version-reference inventory.
   Makefile/installers/release-contract consume the manifest directly.
4. Update exact-version native expectations, portable/provider qualification records,
   support/EOL evidence, migration notes and any notice entry in the same PR.
   Existing historical reports are immutable evidence, not proof for a new patch.
5. Pass every existing Go/API/native/OCI/installed/rehearsal/security gate on the
   candidate. No waiver, automatic retry, matrix shrink or quarantine is added.
   Only a maintainer-reviewed merge can promote the proposed qualification change.

## Discovery and proposals

`tools/qualification/checks/support_window.py propose --revision <full-sha> --output <packet.json>`
reads only the two fixed official GitHub release APIs, at most 100 entries each.
It removes release bodies/assets and retains at most 2 MiB. Patch suggestions stay
inside the current minor window; new minors are separate retirement-review items.
Dates and version syntax are validated. Unknown upstream support remains a required
human review, not a guessed support claim. Offline tests use `--catalog`.

The `support-window.yml` workflow publishes a **nonpublishable review artifact**
weekly and on manual request. It changes no version pins, branches or PRs by default.
An explicit manual `create_pull_request=true` can create one draft PR with the
review packet, using a [GitHub-signed commit mutation](https://docs.github.com/en/graphql/reference/mutations#createcommitonbranch),
DCO attribution and an expected-head check. Repeated identical proposals reuse the existing PR; they do not reopen a
closed review. The default-branch revision must match the packet. No merge, tag,
image publication or release is performed. This automation is source/unit qualified;
no live PR creation was exercised or authorized during this development batch.

## Weekly qualification and failures

The existing `ci.yml` weekly schedule exercises the entire declared window:
three Kubernetes API cells, two Keycloak versions with all native shards, and the
six-cell workload/installed workload/portable/fleet matrices. Fail-fast stays off.
The existing scheduled-failure tracker opens/updates the scoped tracking issue;
JUnit/native diagnostics remain available. Adding a proposal workflow does not
replace, reduce or mark any qualification job optional. `release-contract.py`
rejects window/document/matrix divergence through the shared versions checker.

## Removal and end of support

Before first publication, qualification changes remain reviewed development
changes and must describe lost coverage in CHANGELOG. No nonexistent public
upgrade path or community approval may be manufactured. After publication,
announce a minor removal under the proposed compatibility rules: at least two
subsequent public minor releases and 90 calendar days, plus a migration note and
upstream EOL reference. Both thresholds apply; #87 must ratify them first.

Record the announcement in the machine notice registry and release notes. Confirm
available upgrade/rollback evidence, then retire the pin and all derived matrix
entries in one reviewed PR. Upstream EOL or an urgent security condition cannot
be overridden by project grace: record the shortened-support exception and the
safe migration/containment advice. Historical evidence stays preserved. No
production-support promise is active while publication and review are pending.
