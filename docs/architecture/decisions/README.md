# Architecture decisions

These records preserve the accepted decisions already referenced by the extracted
operator. Their numbers and subjects originate in the platform repository's `adr/`
directory. Reconstructed on 2026-10-14, they describe the enforcing code and tests
in this repository, including subsequent hardening and current qualification
limits. Historical platform API contracts, unimplemented proposals and obsolete
security claims are not imported as operator guarantees. Accepted architecture
does not imply public API stability or completed installed-system qualification.

| Record | Subject |
| --- | --- |
| [ADR-009](ADR-009-kubernetes-operator.md) | Declarative reconciliation and dependency boundaries |
| [ADR-010](ADR-010-hub-pull-distribution.md) | Optional Hub pull distribution and supervision |
| [ADR-017](ADR-017-image-supply-chain.md) | Image policy at the workload submission boundary |
| [ADR-021](ADR-021-administrative-credential-lifecycle.md) | Administrative credential authority and recoverable rotation |
| [ADR-022](ADR-022-keycloak-url-validation.md) | Keycloak URL validation and metadata endpoint exclusion |
| [ADR-029](ADR-029-provider-neutral-authorization.md) | Typed, capability-aware provider authorization |
| [ADR-044](ADR-044-structural-image-trust.md) | Structural OCI registry and repository identity |
| [ADR-047](ADR-047-signed-workload-approvals.md) | Signed immutable image approvals |
| [ADR-048](ADR-048-full-pull-request-qualification.md) | Full qualification matrix on pull requests |
| [ADR-049](ADR-049-locally-approved-fleet-plans.md) | Locally approved signed fleet plans |
| [ADR-050](ADR-050-experimental-lifecycle-authority.md) | Experimental lifecycle exclusion and independent approval |

## Adding or updating a decision

Copy [TEMPLATE.md](TEMPLATE.md) to `ADR-NNN-lowercase-title.md`. Use a unique
positive number padded to at least three digits. Preserve inherited numbers and
gaps; for a new decision use the next number above the highest existing record.
Do not renumber or reuse an ID. Write the full ID at each reference, including
each member of a list. The checker also recognizes inherited slash shorthand.

Document context, decision, consequences and links to the enforcing code and
regression tests. Explain compatibility and qualification limits. Proposals stay
in issues/RFCs until accepted; committed records use `Status: Accepted`. When a
later accepted decision replaces a rule, retain the old record and explain the
relationship with links in both records. Do not erase the original decision.
Update affected records alongside implementation changes.

Reference a decision from relevant Go, YAML or Markdown outside its own file.
Listing it here or in the template does not count as use. Do not add unrelated
historical decisions solely to fill numbering gaps.

Run `python3 -m tools.quality.check_adr_references` and
`python3 -m unittest discover -s tests/tooling -t . -p 'test_adr_references.py'`.
The checker scans tracked and new non-ignored `.go`, `.yaml`, `.yml` and `.md`
files, including hidden configuration and generated manifests. It reports
dangling references with file/line, duplicate or invalid IDs, incomplete records
and orphan records. The tests also verify local code/test links. They run in the
development and CI preflight; CI's required source job runs the checker explicitly.
