# Engineering phases

All ten GitHub milestones have been renamed in place from prelaunch version
labels to non-SemVer phases. Their IDs/numbers/links, issue associations,
open/closed states, creation/closure dates and due dates are preserved. Relevant
descriptions remain; Phase 1's #21 dependency is clarified, and Phase 10's
contract/conformance/migration scope is interpreted as initial-public readiness
without an absolute SemVer 1.0 compatibility promise.

| Historical planning label | Current engineering phase | Existing milestone | State | Issues |
| --- | --- | --- | --- | --- |
| 0.1.0 — Trusted Keycloak Foundation | Phase 1 — Trusted Keycloak Foundation | [1](https://github.com/Alien6-Studio/hankoshell-operator/milestone/1) (ID 18410497) | open | #21 |
| 0.2.0 — IAM Contract Engine | Phase 2 — IAM Contract Engine | [2](https://github.com/Alien6-Studio/hankoshell-operator/milestone/2) (ID 18410498) | closed | #22, #23, #26, #27, #28 |
| 0.3.0 — Application Identity | Phase 3 — Application Identity | [3](https://github.com/Alien6-Studio/hankoshell-operator/milestone/3) (ID 18410499) | closed | #24, #25 |
| 0.4.0 — Organizational Authorization | Phase 4 — Organizational Authorization | [4](https://github.com/Alien6-Studio/hankoshell-operator/milestone/4) (ID 18410500) | closed | #40, #41, #42 |
| 0.5.0 — Adopt Existing Keycloak | Phase 5 — Adopt Existing Keycloak | [5](https://github.com/Alien6-Studio/hankoshell-operator/milestone/5) (ID 18410501) | closed | #46, #47, #48, #49 |
| 0.6.0 — Workload Identity | Phase 6 — Workload Identity | [6](https://github.com/Alien6-Studio/hankoshell-operator/milestone/6) (ID 18410502) | open | none |
| 0.7.0 — Delegation & Agent Identity | Phase 7 — Delegation & Agent Identity | [7](https://github.com/Alien6-Studio/hankoshell-operator/milestone/7) (ID 18410503) | open | none |
| 0.8.0 — Provider Portability Preview | Phase 8 — Provider Portability | [8](https://github.com/Alien6-Studio/hankoshell-operator/milestone/8) (ID 18410504) | open | none |
| 0.9.0 — Fleet Reconciliation | Phase 9 — Fleet Reconciliation | [9](https://github.com/Alien6-Studio/hankoshell-operator/milestone/9) (ID 18410506) | open | none |
| 1.0.0 — Stable Hanko IAM Contract | Phase 10 — Initial Public Contract Stabilization | [10](https://github.com/Alien6-Studio/hankoshell-operator/milestone/10) (ID 18410507) | open | none |

Phases 1–5 supply the implemented foundation. Phase 1 remains open for #21's
transversal trust/readiness evidence; Phases 2–5 stay closed. Phases 6–10 are open
and required before the first public **0.1.0**. No public release is assigned to
an individual phase. #21 retains its content, open state and Phase 1 association;
its first-publication trust criteria also feed Phase 10's exit gate.

The complete capability trajectory formerly planned through the old stable IAM
contract goal is now the maturity path of 0.1.0. Phase 10 is Initial Public
Contract Stabilization: robust conformance and migrations with explicit alpha
limits, not a promise to graduate all resources or guarantee provider parity.
A later 1.0 decision follows real public/production use and a proven compatibility
commitment; no current milestone promises that version. Progress uses issues,
RFCs, PRs, commits and CI, without SemVer or alternative checkpoint tags.
