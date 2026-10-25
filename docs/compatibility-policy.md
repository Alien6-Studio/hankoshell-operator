# Compatibility and deprecation policy

The operator's first public release is
[v1.0.0](https://github.com/Alien6-Studio/hankoshell-operator/releases/tag/v1.0.0),
published on 2026-10-24. Its `v1alpha1` APIs remain experimental. The stable API
commitment below remains a proposal; release approval does not ratify it.
Existing
[API migration rules](api-migration-policy.md), [selection](public-contract-selection.md),
[stable graduation](stable-graduation.md), [support window](support-window.md) and
[runbook limitations](operations-runbooks.md) retain their narrower meanings.

The [machine registry](../tools/qualification/config/contracts/compatibility-policy.json)
tracks proposed stable compatibility baselines and their release/notice history.
No stable baseline, associated release history, notices or exceptions have been
activated there. It is not the operator's publication catalog; published versions
are listed in [Releases](https://github.com/Alien6-Studio/hankoshell-operator/releases).
Ratification requires a separate reviewed change.

## Proposed rules for published public fields

A public release records its exact chart/image/source, schema/defaulting/ownership
fixtures and supported window. Add optional fields only after reviewing old stored
objects and old readers. Keep observable defaults, enums, validation, plan identities,
list/map topology, ownership markers and transaction journals compatible within
an announced public version. A rename includes a removal; adding a replacement
field does not hide the old field's loss. Security tightening is still a behaviour
change and needs an advisory and a migration/rollback assessment.

Announce deprecation in CHANGELOG and the machine notice registry with kind,
version, exact field path/rule, old/new hashes, announcement release/date, reviewed
migration note and review reference. Allow removal only after at least **two
subsequent public minor releases and 90 calendar days**, whichever finishes later.
A new documentation timestamp or a development build does not satisfy the wait.
Security/EOL exceptions need an explicit reviewed notice, advisory and limitations;
there is no automatic compatibility bypass flag.

The latest patch in the latest published public minor receives security fixes;
older minors, prereleases, development builds and forks have no separate backport
commitment or LTS branch. This matches SECURITY.md. A release's upstream eligibility
and exact qualification window must be recorded. Rollback is supported only where
real retained release fixtures reproduce it. Never call same-source Helm
configuration rollback a public operator/provider/data rollback.

Actual installations and upgrade paths use the [sanitized reporting procedure](production-evidence.md)
and [per-release evidence reporting](production-evidence.md). No reviewed public
production compatibility report is recorded. Release qualification and private
installations do not automatically populate that registry.

Helm does not migrate CRDs. A served/storage version change needs a conversion
decision, lossless round-trip fixtures, resumable migration, storedVersions review
and actual upgrade/rollback evidence. Pending approvals, rotations, adoptions and
delegations must remain readable or fail closed before migration starts. No CRD
recreation, field pruning or forced finalizer removal is an upgrade procedure.

## Executable guard and current limits

With no activated stable baseline,
`tools/qualification/checks/compatibility_gate.py` still reports
`NoPublishedPredecessor`. This describes the retained compatibility evidence,
not the availability of v1.0.0. It does not turn the experimental schema into a
stable commitment. Against a future
reviewed stable baseline it names removed/renamed fields, newly required fields,
changed defaults, enum narrowing, validation/pattern/CEL tightening, type/format
changes, list/map topology and unknown-field preservation changes. Exceptions
are bound to exact old/new hashes, an actual announcement history, review and
migration-note references, the two-minor/90-day thresholds and release notes.

Adversarial fixtures test the guard with synthetic stable schemas; those are
**gate tests, not real historical release qualification**. Capturing a current
schema via `snapshot` produces a candidate artifact and never activates a baseline.
The [Go fixture contract](go-api-contract.md) checks compiler-resolved exports.
Real API tests cover the 17 `v1alpha1` schemas, including typed read-back,
concurrent SSA, defaulted specs/status, ownership/finalizers and strict
unknown-field rejection. Future served/storage changes and deprecations require
explicit review.

The published v1.0.0 artifacts are the starting point for subsequent cross-release
qualification. Retaining and reviewing that baseline remains separate from
publishing the operator or graduating its API. Each later delivery still requires
final-candidate qualification and independent release approval.

To introduce a future legitimate deprecation, retain the published baseline,
add the hash-bound announcement and migration note, obtain its recorded review,
wait for both notice thresholds, then let the gate compare the proposed schema.
Do not update a baseline to the candidate just to suppress a failure. Publish and
review authentic historical artifacts through the existing release process.
