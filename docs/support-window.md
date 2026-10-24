# Kubernetes and Keycloak qualification/support window

The `v1alpha1` API remains in **initial development**; this policy defines its qualification window.
It does not publish a release or grant stable API compatibility. The proposed
public rules in [compatibility-policy.md](compatibility-policy.md) await #87's
post-publication community review. Machine rules live in
[compatibility-policy.json](../tools/qualification/config/contracts/compatibility-policy.json); exact versions and immutable
fixture checksums live only in [versions.json](../versions.json).

Upstream review, 2026-10-24: Kubernetes 1.35, 1.36 and 1.37 are maintained
[release series](https://kubernetes.io/releases/). Their fixture patches are
compatibility samples; deploy current upstream security patches. Keycloak
[26.8.1](https://www.keycloak.org/2026/10/keycloak-2681-released) supplies security
fixes and replaces 26.8.0 in the current matrix. The retained 26.7.5 cell measures
older-minor compatibility, not an upstream backport commitment. Existing 26.8.0
workload declarations remain readable; new installations should use the patched provider.

<!-- support-window:start -->
| Component | Exact qualification versions | Default |
| --- | --- | --- |
| kubernetes | `1.35.0`, `1.36.2`, `1.37.0` | `1.37.0` |
| keycloak | `26.7.5`, `26.8.1` | `26.8.1` |
<!-- support-window:end -->

## Window rules

The table records **exact tests**, not a runtime patch allowlist. Core fleet
rollout accepts canonical stable `26.x` versions. Kubernetes workload federation
and bounded delegation are eligible from `26.7.5` within that major; discovery
overrides require `26.8.0` or later `26.x`. New patches and minors do not require
an operator rebuild merely to pass a version check. Unmeasured versions are not
reported as qualified. Prereleases, vendor suffixes and new major versions are
excluded from these feature declarations until reviewed.

Version eligibility never grants permissions or bypasses native ownership,
discovery or resolved-source read-back. Bounded delegation additionally requires
the exact enabled extension contract and its depth/TTL limits. Missing optional
capabilities refuse that feature, rather than disabling ordinary reconciliation.
Core reconciliation and the experimental managed `Upgrade` operation do not
impose a global server-version allowlist. An older server is not thereby qualified.

An accepted version is also not a guarantee of a rolling or reversible upgrade.
Use Keycloak's [update compatibility check](https://www.keycloak.org/server/update-compatibility)
and [migration guide](https://www.keycloak.org/docs/latest/upgrading/): even bug or
security fixes may change behavior, and database migrations can require restoring
a backup to return to the old server. The operator's existing backup, readiness
and observation checks remain in force.

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

1. Review the official Kubernetes and Keycloak release notes. Reject
   prereleases, drafts, future dates, major/minor surprises and unsupported upstream
   branches. Review patch notes, native semantics and security urgency.
2. In the same reviewed PR, edit `versions.json` and supply actual reviewed image
   digests, envtest checksums and node fixtures. Verify checksums against the
   upstream release assets.
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

## Weekly qualification and failures

The existing `ci.yml` weekly schedule exercises the entire declared window:
three Kubernetes API cells, two Keycloak versions with all native shards, and the
six-cell workload/installed workload/portable/fleet matrices. Fail-fast stays off.
The existing scheduled-failure tracker opens/updates the scoped tracking issue;
JUnit/native diagnostics remain available. `release_contract.py`
rejects window/document/matrix divergence through the shared versions checker.

## Removal and end of support

The first public release is v1.0.0. Qualification changes must describe lost
coverage in CHANGELOG. No unmeasured public upgrade path or community approval
may be claimed. Announce a minor removal under the proposed compatibility rules:
at least two subsequent public minor releases and 90 calendar days, plus a migration note and
upstream EOL reference. Both thresholds apply; #87 must ratify them first.

Record the announcement in the machine notice registry and release notes. Confirm
available upgrade/rollback evidence, then retire the pin and all derived matrix
entries in one reviewed PR. Upstream EOL or an urgent security condition cannot
be overridden by project grace: record the shortened-support exception and the
safe migration/containment advice. Historical evidence stays preserved. No
additional production-support promise follows from publication alone; the API
remains experimental and the proposed stable commitment requires its own review.
