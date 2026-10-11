# Engineering milestone title proposal

This is a proposal, not an executed GitHub administration change. Existing
SemVer-shaped titles identify historical engineering milestones and do not
assign public product versions. Public releases use release/v<SemVer> tags,
starting with product 0.1.0 after source, tag and production-trust authorization.

## Inspected GitHub state

| Stable milestone ID/link | Existing title | Proposed title | State | Open / closed issues |
| --- | --- | --- | --- | --- |
| [1](https://github.com/Alien6-Studio/hankoshell-operator/milestone/1) | 0.1.0 — Trusted Keycloak Foundation | E1 — Trusted Keycloak Foundation | open | 1 / 0 |
| [2](https://github.com/Alien6-Studio/hankoshell-operator/milestone/2) | 0.2.0 — IAM Contract Engine | E2 — IAM Contract Engine | closed | 0 / 5 |
| [3](https://github.com/Alien6-Studio/hankoshell-operator/milestone/3) | 0.3.0 — Application Identity | E3 — Application Identity | closed | 0 / 2 |
| [4](https://github.com/Alien6-Studio/hankoshell-operator/milestone/4) | 0.4.0 — Organizational Authorization | E4 — Organizational Authorization | closed | 0 / 3 |
| [5](https://github.com/Alien6-Studio/hankoshell-operator/milestone/5) | 0.5.0 — Adopt Existing Keycloak | E5 — Adopt Existing Keycloak | closed | 0 / 4 |
| [6](https://github.com/Alien6-Studio/hankoshell-operator/milestone/6) | 0.6.0 — Workload Identity | E6 — Workload Identity | open | 0 / 0 |
| [7](https://github.com/Alien6-Studio/hankoshell-operator/milestone/7) | 0.7.0 — Delegation & Agent Identity | E7 — Delegation & Agent Identity | open | 0 / 0 |
| [8](https://github.com/Alien6-Studio/hankoshell-operator/milestone/8) | 0.8.0 — Provider Portability Preview | E8 — Provider Portability Preview | open | 0 / 0 |
| [9](https://github.com/Alien6-Studio/hankoshell-operator/milestone/9) | 0.9.0 — Fleet Reconciliation | E9 — Fleet Reconciliation | open | 0 / 0 |
| [10](https://github.com/Alien6-Studio/hankoshell-operator/milestone/10) | 1.0.0 — Stable Hanko IAM Contract | Public IAM/API stability review | open | 0 / 0 |

All IDs/URLs, issue associations and states are retained. E1 stays open for #21;
E2–E5 are closed, and E6–E9 and the independent API stability review remain open.
There is no E6 = 0.2.0 or E7 = 0.3.0 mapping. Public 1.0.0 requires a reviewed
stable contract, compatibility policy and mature migration/conversion evidence,
not completion of a tenth engineering milestone.

## Why no rename is performed

The repository workflows/scripts contain no milestone-title automation, but the
available inspection cannot prove that GitHub Projects, installed applications
or external automation have no title dependencies. This leaves the required
no-automation-dependency criterion unestablished. Keep the original GitHub titles
and qualify them as historical engineering milestones in repository documentation.

Before any separately reviewed rename, an administrator must inventory those
automations and record each milestone's number/URL, issue IDs and open/closed
state. Update only the existing title, then compare those invariants; do not delete
or recreate a milestone or issue, transfer issues or change milestone state.
