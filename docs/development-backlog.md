# Development backlog for the 1.0 workstream

Snapshot: 2026-10-19, `feat/1.0.0-dev`. There are **20 open issues**.
Recent batches repaired and requalified #71/#95; they did not complete the rest
of this backlog. The branch name does not announce a stable API or public release.

| Tracking category | Count | Issues and remaining work |
| --- | ---: | --- |
| `track:qualification` | 4 | #71 installed delegation; #86 complete initial candidate; #95 capacity/endurance/sizing; #96 complete HA transaction and fault matrix |
| `track:stable-roadmap` | 14 | #87, #88, #89, #91, #92, #93, #94, #99, #101, #103, #104, #105, #106, #107: remaining stable implementation, public history, decisions and delivery |
| `track:external-evidence` | 2 | #21 independently verified publication trust; #110 usable twenty-consecutive-main-run history |

These groups preserve all acceptance criteria. The stable-roadmap group contains
real implementation work; independent work can proceed before the public-history
and ratification prerequisites. A source push cannot create those external proofs.

Develop related changes before running shared source/API/provider gates. Keep
long installed/soak runs in isolated immutable worktrees. Push signed batches and
close completed implementation issues according to CONTRIBUTING.md, with the
exact commit and available validation. Incomplete implementation or required
qualification remains open with its actual missing criteria.

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
