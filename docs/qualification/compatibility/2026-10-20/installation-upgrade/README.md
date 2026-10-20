# Existing installation upgrade

The existing Scaleway development operator was upgraded in place on 2026-10-20.
The [rollout report](rollout.json) records the immutable images, current-generation
read-back and preservation checks. All 109 original declaration UIDs, 16 original
CRD UIDs and the operator Deployment UID survive the upgrade. Seventeen CRDs are
installed; alpha remains storage. This is a real private development predecessor,
not a published release or a completed public upgrade/rollback qualification.

Native ownership was acquired for 57 reviewed targets. Thirty Applications,
13 Organizations, four Roles, two ServiceAccounts and eight ResourceServers have
resumed their original Manage mode and are Ready at the current generation. The
ResourceServers resumed after explicit consent and a fresh no-change graph review.
Imported Observe aliases remain passive. All 27 common acquisition receipts are
Verified; Applications use their existing UUID/observation migration path.

The old Deployment's Fleet authority realm is explicitly retained in the new
chart values and cross-checked with the tracked platform configuration. Reusing
only the old Helm values had temporarily selected the new chart's different
default, correctly blocking the existing authority realm's role reconciliation.
The final rollout restores the prior setting and keeps the reserved-role guards.

Seven themes are Ready. Three legacy mutable builder references were migrated
using the platform's existing reviewed mapping to an already-approved signed
image. Native client UUIDs, configuration, mappers, roles and scope collections
are preserved for all 30 managed applications. All 32 credential output targets
retain their UID; 30 retain their data. Two ServiceAccount credentials rotated
early after Observe/acquisition cleared their previous rotation timestamp. Both
updated outputs authenticate successfully, with no Pod or workload-template
consumers found in the cluster. This is a retained preservation failure, not an
all-credentials-unchanged result. Theme installation restarted the existing
single-replica Keycloak through its normal workflow; this is not a zero-downtime
claim. The temporary CPU quota increase was restored after the builds.

An application login incident subsequently showed that Ready conditions and
unchanged Secret data do not prove consumer health. The dashboard process still
held an older OIDC credential in its environment, while its current Kubernetes
Secret already matched Keycloak. Its failures also triggered a temporary proxy
lockout. Rolling only that Deployment loaded the current credential without
changing its image, settings or Secret. Discovery returned 200 from the new Pod;
an anonymous browser rendered the login form without failed assets, and the public
token endpoint accepted the client's authentication. No human account session was
tested. Automatic consumer reload remains an installation prerequisite for
unattended rotation; this rollout did not install a reload mechanism.

The migration exposed four recovery cases, covered by the accompanying fixes:

- Three legacy M2M clients carry both catalog hints. Preserve the extra true hint
  without weakening protocol, authentication, ownership or required-hint checks.
- A provider outage can leave a stale conflicting receipt in status after native
  acquisition. Fresh native verification repairs that output while retaining
  applied-plan and credential checkpoints.
- A controller may add its cleanup finalizer between explicit Manage consent and
  the claim CLI's read-back. Accept only that exact addition after consent; other
  metadata changes still invalidate the plan.
- Observe/acquisition must retain the historical service-account rotation time.
  Clear active credential references and schedules while preserving that checkpoint,
  so a later explicit Manage resume does not trigger an early rotation. Regression
  tests cover acquisition and two complete Observe/Manage round trips.

The recovery revision `1ad60cd` passes affected Go race tests and real HTTPS
legacy migration on the supported 26.7.5/26.8.0 matrix, plus private 26.7.3
characterization with the same Go files. The final checkpoint revision `7d235f8`
passes the complete controller race suite, targeted mode-transition tests,
477 Python tests, preflight and hooks. Both architectures of its exact deployed
OCI pass the vulnerability policy
with no exceptions or HIGH/CRITICAL findings. The private legacy fixture does not
extend public support. Rollout evidence does not satisfy the separate >=24-hour
endurance, larger capacity, public predecessor or stable publication criteria.

## Retained preflight evidence

- [Schema replay](schema-replay.json): all reads and strict dry-run updates
  preserve existing spec/status after accounting only for the listed defaults.
  No old field or existing value is discarded. Local UIDs and field managers
  differ, so this does not prove native ownership or SSA ownership transfer.
- [Chart preflight](chart-preflight.json): the Deployment selector and service
  account remain unchanged. The private proposal preserves integrations, declares
  27 exact existing output Secret targets and explicitly retains the legacy HTTP
  compatibility setting. Its image is the previous qualified development image;
  see the rollout report for the images subsequently scanned and installed.
- [Native ownership inventory](ownership-inventory.json): metadata-only provider
  reads examined 71 declarations. All native targets exist; 44 Manage objects
  lack the current UID ownership marker: 30 applications, two service accounts,
  four roles and eight resource servers. The other 27 are Observe/imported.
  The [extended Organization inventory](organization-ownership.json) additionally
  checks 13 structural groups: all lack the current markers, while the native
  Organization root has its exact target owner. This raises the audited
  declaration count to 84 and the Manage review count to 57. These historical
  pre-acquisition counts are superseded by the rollout read-back above.
- [Validation identities](validation.json): the current IAM contract passes with
  race detection against real HTTPS Keycloak 26.7.3 in a local disposable
  container. Only that legacy image pin was added in the private source copy.
  Adoption characterization also passes on that version. These targeted
  experiments do not extend the public support matrix or qualify every deployed
  target for acquisition.
- [Migration regressions](migration-regressions.json): 72 passing race outcomes
  across real HTTPS 26.7.3, 26.7.5 and 26.8.0 cover legacy/common client migration
  and aggregate Organization acquisition, including an already-owned native root.
  The private 26.7.3 fixture adds its image pin and uses the observed legacy
  credential-visibility expectation. The first mismatched assertion is retained;
  no production permission or credential-route restriction was relaxed.

A plain image replacement would leave unmarked Manage resources refused by the
new ownership checks. The [native settings inventory](native-settings.json)
finds native scope collections on all 30 Manage applications, disabled
frontchannel logout on 28 and protocol mappers on 12. These are anonymous counts;
no native values, identifiers or credentials are published. The migration fixes
preserve bounded scope references/logout, normalize native set ordering and avoid
reattaching `service_account` during legacy migration or subsequent updates.
The rollout used an independent read-only inventory, reviewed native preservation
and exact acquisition candidates, and used the existing
[adoption workflow](../../../../architecture/existing-keycloak-adoption.md#implemented-reviewed-leaf-acquisition-48).
Preserve native UUIDs, declaration UIDs, credentials and journals. Do not invent
owner attributes, clear status or recreate clients to make an upgrade appear
successful. Aggregate acquisition has its own preservation/dependency review.

The rollout retains private backups, reviewed field ownership and transaction
checks, signed theme verification and current-generation/provider read-back.
Rollback remains a separate unexecuted qualification. Schema and provider-version
checks alone do not establish safe takeover.
