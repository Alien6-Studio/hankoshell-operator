# Proposed public 0.x compatibility and deprecation policy

Status: **prepublication proposal**, pending community review in #87 after the
first qualified public release. No review start/end, acceptance, public release,
stable API or upgrade evidence is fabricated. Current v1alpha1 APIs remain
experimental. 0.x does not make a 1.0 SemVer commitment. Existing
[API migration rules](api-migration-policy.md), [selection](public-contract-selection.md),
[stable graduation](stable-graduation.md), [support window](support-window.md) and
[runbook limitations](operations-runbooks.md) retain their narrower meanings.

The [machine registry](compatibility-policy.json) has no public releases,
compatibility baseline, notices or exceptions yet. Ratification is a separate
reviewed change; repository documentation is not evidence of community acceptance.

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

The latest patch in the latest published public 0.x minor receives security fixes;
older minors, prereleases, development builds and forks have no separate backport
commitment or LTS branch. This matches SECURITY.md. A release's upstream eligibility
and exact qualification window must be recorded. Rollback is supported only where
real retained release fixtures reproduce it. Never call same-source Helm
configuration rollback a public operator/provider/data rollback.

Helm does not migrate CRDs. A served/storage version change needs a conversion
decision, lossless round-trip fixtures, resumable migration, storedVersions review
and actual upgrade/rollback evidence. Pending approvals, rotations, adoptions and
delegations must remain readable or fail closed before migration starts. No CRD
recreation, field pruning or forced finalizer removal is an upgrade procedure.

## Executable guard and current limits

`scripts/compatibility-gate.py` reports `NoPublishedPredecessor` today. It does
not turn the experimental schema into a stable commitment. Against a future
reviewed stable baseline it names removed/renamed fields, newly required fields,
changed defaults, enum narrowing, validation/pattern/CEL tightening, type/format
changes, list/map topology and unknown-field preservation changes. Exceptions
are bound to exact old/new hashes, an actual announcement history, review and
migration-note references, the two-minor/90-day thresholds and release notes.

Adversarial fixtures test the guard with synthetic stable schemas; those are
**gate tests, not real historical release qualification**. Capturing a current
schema via `snapshot` produces a candidate artifact and never activates a baseline.
Stable API conversion/round-trip and exported Go API compatibility remain #91/#94;
real cross-release fixtures remain #93/#101/#105. Their absence cannot be marked
successful by this schema-diff implementation. #94 stays open until those pieces
and a real public baseline exist. #87 stays open for publication and community review.

To introduce a future legitimate deprecation, retain the published baseline,
add the hash-bound announcement and migration note, obtain its recorded review,
wait for both notice thresholds, then let the gate compare the proposed schema.
Do not update a baseline to the candidate just to suppress a failure. Publish and
review authentic historical artifacts through the existing release process;
this batch neither activates nor runs production publication.
