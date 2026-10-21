# Architecture decisions

These decisions use the operator repository's own sequence, starting at 001.
The initial records were adapted from `hanko-platform`; their current IDs are
local to this repository. Accepted architecture does not imply public API
stability or completed installed-system qualification.

| Record | Subject |
| --- | --- |
| [ADR-001](ADR-001-kubernetes-operator.md) | Declarative reconciliation and dependency boundaries |
| [ADR-002](ADR-002-hub-pull-distribution.md) | Optional Hub pull distribution and supervision |
| [ADR-003](ADR-003-image-supply-chain.md) | Image policy at the workload submission boundary |
| [ADR-004](ADR-004-administrative-credential-lifecycle.md) | Administrative credential authority and recoverable rotation |
| [ADR-005](ADR-005-keycloak-url-validation.md) | Keycloak URL validation and metadata endpoint exclusion |
| [ADR-006](ADR-006-provider-neutral-authorization.md) | Typed, capability-aware provider authorization |
| [ADR-007](ADR-007-structural-image-trust.md) | Structural OCI registry and repository identity |
| [ADR-008](ADR-008-signed-workload-approvals.md) | Signed immutable image approvals |
| [ADR-009](ADR-009-full-pull-request-qualification.md) | Full qualification matrix on pull requests |
| [ADR-010](ADR-010-locally-approved-fleet-plans.md) | Locally approved signed fleet plans |
| [ADR-011](ADR-011-experimental-lifecycle-authority.md) | Experimental lifecycle exclusion and independent approval |
| [ADR-012](ADR-012-audited-finalizer-release.md) | Independently approved and audited finalizer recovery |

## Adding or updating a decision

Copy [TEMPLATE.md](TEMPLATE.md) to `ADR-NNN-lowercase-title.md`. Use a unique
positive number padded to at least three digits. For a new decision, use the
next number above the highest existing record.
Write the full ID at each reference, including each member of a list.

Document context, decision, consequences and links to the enforcing code and
regression tests. Explain compatibility and qualification limits. Proposals stay
in issues/RFCs until accepted; committed records use `Status: Accepted`. When a
later accepted decision replaces a rule, retain the old record and explain the
relationship with links in both records. Do not erase the original decision.
Update affected records alongside implementation changes.

Reference a decision from relevant Go, YAML or Markdown outside its own file.
Listing it here or in the template does not count as use. Keep decisions scoped
to this operator.

Review affected references and links alongside the implementation, then run
`make preflight`.
