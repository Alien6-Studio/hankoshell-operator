# Prelaunch version reference inventory

The reset inventoried every tracked old-version occurrence before editing using
`git grep -nE '\b0\.[1-9]\.0\b|v0\.[1-9]\.0|0\.5\.1|1\.0\.0' HEAD`.
A portable follow-up without `\b` includes bare version labels on macOS Git;
its complete category counts are below. Matches were reviewed before path-specific changes. No global repository
replacement was used. The categories and treatment are:

| Category | Original matches | Treatment |
| --- | --- | --- |
| active product metadata / future release contract / adversarial fixture | 78 | Use 0.1.0-dev.0 for active build/chart/app/scan/rehearsal identities, normal v0.1.0 for future publication and a source readiness gate. Keep valid/invalid SemVer fixtures that test independent parsing and production refusal. |
| product documentation / phase mapping / historical note | 153 | Describe first-public development and all ten phases, consolidate changelog domains, retain historical labels only in the migration mapping. |
| API description phase label | 4 | Replace obsolete phase-number comments with current-contract wording; regenerate matching descriptions in the two CRDs without schema changes. |
| capability label / legacy migration contract | 13 | Name IAM/application/organization/adoption capabilities. Preserve omitted-protocol OIDC defaults, legacy marker/UID and observation approval, stored-object migration and provider preservation semantics. |
| external dependency/tool | 43 | Retain all third-party pins and checksums, including native Attest 0.1.0. |
| generic protocol/test fixture | 27 | Retain generic Go self-update/image-approval versions, registry-error fixtures and OCI imageLayoutVersion 1.0.0. |

The source chart icon uses a retained immutable commit, not an old tag. Generated
development metadata uses the actual qualified commit and omits nonexistent
GitHub release-asset links. The future stable candidate uses normal v0.1.0 URLs.

Historical Git commits/PRs/CI and signed objects are retained without history
rewrites. Removing erroneous tag refs does not alter their underlying commits.
Old milestone labels remain only as the explicit phase-mapping audit; later 1.0
mentions describe a future compatibility decision, not a scheduled milestone.
