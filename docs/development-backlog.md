# Development backlog for the 1.0 workstream

Snapshot: 2026-10-17, `feat/1.0.0-dev`. The 22 open issues are grouped below;
this is an execution map, not a claim that their acceptance criteria are met.
The branch name does not announce a stable API or a public release.

| Workstream | Open issues | Work to complete together |
| --- | --- | --- |
| Delegation | #69, #70, #71 | Native exchange, authority intersection/depth/lifetime, then actual installed token flows |
| Stable APIs and compatibility | #89, #91, #92, #93, #94, #101, #105 | Surface decision, conversion/storage migration, real predecessor and adoption upgrade/rollback fixtures, compatibility enforcement |
| Security and reliability | #95, #96, #99, #110 | Scale/soak, HA transaction recovery, parser/admission/RBAC review, real-Keycloak stability evidence |
| Contract, operations and delivery evidence | #21, #86, #87, #88, #103, #104, #106, #107 | Initial qualification, policy/production evidence, runbooks, ratification and independently authorized delivery |

Develop related changes before running the shared source/API/provider gates;
keep expensive installed/soak runs active. Push signed batches to development
and close only issues whose entire acceptance criteria have actual evidence.
A partial implementation remains open with its exact remaining acceptance work.
No merge or publication is performed by this execution map.

## Current batch and next dependencies

The current security/contract batch advances #99 and the guard/runbook portions
of #94/#103: parser fuzzing, explicit CRD bound inventory, named-reference
admission, rendered RBAC review and a reduced leader-lock grant. These do not
satisfy stable conversion or historical public-release qualification.

Next, develop the delegation implementation and its attenuation/revocation
checks together (#69/#70), then run #71's installed flows on the actual provider
capabilities. A refused unsupported intent is not a successful delegation flow.

Stable versions (#91) follow the resource decision in #89; storage movement and
rollback (#92) follow the implemented conversion contract. #93/#101/#105 require
authentic public predecessor artifacts and real paths, not reconstructed or
same-source fixtures. Existing development guard tooling does not fill that gap.

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
