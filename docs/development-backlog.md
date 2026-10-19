# Development backlog for the 1.0 workstream

Snapshot: 2026-10-19, `feat/1.0.0-dev`, after implementation delivery of #91, #92, #94 and #103.
There are **16 open issues at this snapshot**, before the final protected Resolution of #71/#99.
The [complete delegation CI packet](qualification/delegation/2026-10-19/runtime-98659a0/README.md)
now records all twelve installed/HA cells for #71; final integration and closure are pending.
Recent batches advanced repairs and qualification for #95; they did not complete the rest
of this backlog. The branch name does not announce a stable API or public release.

| Tracking category | Count | Issues and remaining work |
| --- | ---: | --- |
| `track:qualification` | 4 | #71 installed delegation; #86 complete initial candidate; #95 capacity/endurance/sizing; #96 complete HA transaction and fault matrix |
| `track:stable-roadmap` | 10 | #87, #88, #89, #93, #99, #101, #104, #105, #106, #107: remaining stable implementation, public history, decisions and delivery |
| `track:external-evidence` | 2 | #21 independently verified publication trust; #110 usable twenty-consecutive-main-run history |

These groups preserve all acceptance criteria. The stable-roadmap group contains
real implementation work; independent work can proceed before the public-history
and ratification prerequisites. A source push cannot create those external proofs.

Develop coherent batches locally, then run shared validation before pushing.
Keep long installed/soak runs in isolated immutable worktrees. Signed pushes record
implementation delivery; integration retains the protected PR and qualification
requirements. Local implementation does not manufacture external evidence or
close partially delivered roadmap issues.

## Delivered compatibility guard tooling (#94)

Schema/default/enum/topology diffs, exact hash-bound deprecation exceptions,
notice timing, typed-reader conversion, concurrent SSA, frozen plan identities
and compiler-resolved Go exports are enforced by the shared make/CI/release gates.
Adversarial tests cover field removal/rename, tighter validation, conversion loss
and legitimate notice requirements. An added default now produces one review
requirement rather than duplicate diagnostics. This records implementation
delivery under CONTRIBUTING.md; authentic public baselines, actual cross-release
paths and final integration qualification remain in their own open workstreams.

## API/storage implementation batch (#91/#92/#94)

Application, Role and ResourceServer gain a served experimental v1beta1 candidate,
lossless object/list conversion and frozen schema equivalence. Alpha remains the
hub/default storage. The administrator utility implements reviewed plans, native
storage rewrite, interruption recovery and separately approved rollback. CRD
preflight preserves live storage and rejects orphaning stored versions; the chart
checks stored-version readability. Conversion fuzzing and a disposable native
fixture cover meaning, authority metadata and actual etcd encoding.

Stable API graduation, resource ratification, production evidence and genuine public predecessor paths
remain distinct acceptance requirements. The migration utility refuses active
rotation/delegation policies until their native state has an independent idle
inspection path; it does not clear their journals to force a migration.

The recovery follow-up interrupts real migration processes after native rewrite
submission and after a first storedVersion commit, in both directions. Resume
still needs fresh native proof and unchanged object meaning. Kubernetes may
already complete and prune storedVersions during the interruption; the fixture
requires that exact succeeded job and physical target encoding in this case.
All three reviewed Kubernetes versions now run this fixture in required CI.
This does not replace real-provider or public cross-release qualification in #92.

Application, Role and ResourceServer status now distinguishes typed provider
authentication, permission, overload, outage, conflict and cancellation failures.
The operational contract binds every fixed reason to its recovery procedure,
while regression tests reject string-spoofed status codes and private messages.
The administrator finalizer-release workflow now supplies independent approval,
immutable audit intent, selective CAS removal and observation without replay.
Its actual CLI/admission witness passes on all three reviewed Kubernetes versions.

## Current HA and security batch

Delegation implementation #69/#70 is delivered through the pinned standalone
Keycloak extension. #71's complete installed/HA CI packet supersedes its earlier
failed-cell gaps. Historical failures remain retained; final protected Resolution
and closure must follow the current integration.

The current batch advances #96/#99 together: caller-scoped loss of the live
leader's API access, natural lease handoff and per-caller provider-write checks;
a required six-cell HA CI matrix; canonical runtime cleanup journals; and fuzzing
of runtime target authority plus native delegation recovery envelopes. HA is
separate from the load job, so it can run without repeating the 1,000-object
profile. Started or implemented scenarios are not completed installed evidence.

The next HA fixture covers delegation apply at all four native phases across
two-replica handoff, separately from restart/status-loss tests. The six-cell HA
job requires both fixtures and retains their independent reports. Installed
completion must still be measured; implementation alone is not a passing cell.
Remaining #96 scope includes arbitrary partitions and clock skew, plus the full
retained candidate matrix, outage coverage and endurance prerequisites.
The [#99 instrumented audit](qualification/security/2026-10-19/bounded-contract/README.md)
now records complete field budgets, conversion/parser fuzzing and the admission/RBAC
review. Its report route satisfies the issue's external-review-or-audit requirement;
the current exact-image installed CI and protected Verified Resolution remain mandatory.

The version/conversion implementation (#91) and storage movement/rollback (#92)
are delivered for the three reviewed IAM candidates. Their beta version remains
experimental; stable resource selection and compatibility ratification remain
in #89/#104. #93/#101/#105 require authentic public predecessor artifacts and real
paths. Implementation delivery does not provide those historical proofs.

## Evidence that code alone cannot create

- #21 needs independently provisioned/verified production trust and catalog
  ownership. It does not authorize a tag, release or public registry write.
- #87/#89/#104 require actual community/contract decisions; a draft document is
  not ratification. Graduation currently requires production evidence and no
  resource has graduated.
- #88 requires real sanitized installation/incident/upgrade reports after public
  delivery. Two fixture clusters are not independent production installations.
- #110 needs the stated consecutive real test/main-run history. A local streak
  does not replace the required main history.
- #95 needs a completed 24-hour soak; #96/#99 need their complete installed
  matrices. Started runs, parser tests and empty incomplete scan output are not
  completed qualification.
- #86/#106 aggregate exact-candidate evidence. #107 additionally needs independent
  verification and the second-maintainer/environment approval specified there.

Production publication remains a separate action; the development backlog does
not waive the existing trust, review or qualification requirements.

Some issue descriptions also have closure-link cycles: #104 asks for links to
#105/#106/#107 while those issues depend on #104, and #106 asks for all milestone
issues closed before #107. Track contract decisions, implementation completion
and final delivery evidence separately; do not fabricate closures to satisfy
such a cycle. Reconcile those issue dependencies in the final acceptance review.


## Security and operations implementation follow-up (#99/#103)

The IAM admission budget reduces the inventory gaps from 440 to 397 across the
20 served schemas. Per-kind CR grants replace the blanket writer; live
authorizer/admission fixtures cover both lifecycle profiles. An offline incident
collector exports only anonymous fixed decisions and generation/count evidence,
with bounded parsing and private exclusive output. Stable field/RBAC acceptance,
independent review and public upgrade evidence remain unfinished in #99 and the
release qualification issues. The audited finalizer-release mechanism is delivered.

## Operational procedures delivered (#103)

Installation, upgrade/rollback, native storage migration, leader/provider
recovery, rotation/audit refusal, adoption/finalizer release, Fleet/delegation,
decommission and private incident collection now have explicit commands,
executable fixture references and qualification limits. The operational contract
checks eleven procedure records across all eight runbook groups and rejects
missing commands, missing fixtures and erased unqualified notices.

Connected installation/decommission and public predecessor paths remain explicitly
unqualified; #103 allows untested procedures when marked. Their actual installed
or public-release evidence belongs to #86/#93/#101/#105/#106. Closing this
documentation/operational implementation issue does not qualify those paths or
graduate an API. Full protected integration remains required independently.

## API and native storage delivery (#91/#92)

The [current CI delivery packet](qualification/recovery/2026-10-19/api-storage-delivery/README.md)
records passing API/security and native storage jobs on Kubernetes 1.35.0,
1.36.2 and 1.37.0. Three fresh native reports prove 48 physical migrations and
twelve real process interruptions with same-plan resume and alpha/beta rollback.
Their artifact digests, source-component hashes and job links are retained.

The implementation issues close under the push-based delivery rule in
CONTRIBUTING.md. This does not mark the complete aggregate pipeline green,
qualify a real-provider/public predecessor upgrade, or ratify a stable API.
Those proofs and decisions remain in their dedicated open issues.
