# Development backlog for the 1.0 workstream

Snapshot: 2026-10-19, `feat/1.0.0-dev`, after implementation delivery of #94.
There are **19 open issues**.
Recent batches advanced repairs and qualification for #71/#95; they did not complete the rest
of this backlog. The branch name does not announce a stable API or public release.

| Tracking category | Count | Issues and remaining work |
| --- | ---: | --- |
| `track:qualification` | 4 | #71 installed delegation; #86 complete initial candidate; #95 capacity/endurance/sizing; #96 complete HA transaction and fault matrix |
| `track:stable-roadmap` | 13 | #87, #88, #89, #91, #92, #93, #99, #101, #103, #104, #105, #106, #107: remaining stable implementation, public history, decisions and delivery |
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
The generic independently approved/audited finalizer-release workflow remains
unfinished in #103; existing Observe transitions do not implement it.

## Current HA and security batch

Delegation implementation #69/#70 is delivered through the pinned standalone
Keycloak extension. #71 still needs complete installed qualification; earlier
failed cells and incomplete endurance intervals remain retained as failures.

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
Remaining #99 scope includes stable conversion/storage fuzzing, complete stable
admission/RBAC review, installed adversarial evidence and independent review.

Stable versions (#91) follow the resource decision in #89; storage movement and
rollback (#92) follow the implemented conversion contract. #93/#101/#105 require
authentic public predecessor artifacts and real paths. Development guard tooling
is already delivered in part; it does not provide those historical proofs.

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
