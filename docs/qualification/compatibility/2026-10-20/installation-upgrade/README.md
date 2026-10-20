# Existing installation upgrade preflight

The requested in-place upgrade remains the target. Read-only inspection and a
private disposable Kubernetes 1.35.0 replay checked the existing installation's
109 declarations. No live CRD, declaration, Secret or provider configuration was
changed. This is an actual private development predecessor, not a published
release or a completed upgrade/rollback qualification.

- [Schema replay](schema-replay.json): all reads and strict dry-run updates
  preserve existing spec/status after accounting only for the listed defaults.
  No old field or existing value is discarded. Local UIDs and field managers
  differ, so this does not prove native ownership or SSA ownership transfer.
- [Chart preflight](chart-preflight.json): the Deployment selector and service
  account remain unchanged. The private proposal preserves integrations, declares
  27 exact existing output Secret targets and explicitly retains the legacy HTTP
  compatibility setting. Its image is the previous qualified development image;
  the current batch still needs its own scanned OCI and installed qualification.
- [Native ownership inventory](ownership-inventory.json): metadata-only provider
  reads examined 71 declarations. All native targets exist; 44 Manage objects
  lack the current UID ownership marker: 30 applications, two service accounts,
  four roles and eight resource servers. The other 27 are Observe/imported.
  Organization and complete native transaction ownership were not audited.
- [Validation identities](validation.json): the current IAM contract passes with
  race detection against real HTTPS Keycloak 26.7.3 in a local disposable
  container. Only that legacy image pin was added in the private source copy.
  Adoption characterization also passes on that version. These targeted
  experiments do not extend the public support matrix or qualify every deployed
  target for acquisition.

A plain image replacement would leave unmarked Manage resources refused by the
new ownership checks. Prepare their independent read-only inventory, review
native preservation and exact acquisition candidates, then use the existing
[adoption workflow](../../../../architecture/existing-keycloak-adoption.md#implemented-reviewed-leaf-acquisition-48).
Preserve native UUIDs, declaration UIDs, credentials and journals. Do not invent
owner attributes, clear status or recreate clients to make an upgrade appear
successful. Aggregate acquisition has its own preservation/dependency review.

The rollout also needs reviewed field ownership, pending transaction checks,
image trust, rollback and current-generation/provider read-back. Schema and
provider-version checks alone do not satisfy those requirements. A persistent
24-hour campaign measures endurance separately; it cannot substitute for an
in-place upgrade.
