# ADR-011: Experimental lifecycle exclusion and independent approval

Status: Accepted

## Context

#20 added durable
operation/snapshot checkpoints, UID-bound children, interruption recovery and
current managed-rollout verification. The installed fixture qualifies a
same-namespace, configuration-only Clone alias using a read-only external
Keycloak source. It does not qualify managed Upgrade/DBSwitch, copying a
database, portable restore, or database consistency. Allowing any operation
author to select image/database references would also delegate instance-writer
authority implicitly. #102 requires an explicit 1.0 decision and authority gate.

## Decision

`HankoOperation` and `HankoSnapshot`, including every spec/status field, are
**experimental and excluded from the stable 1.0 contract**. Keep `v1alpha1`, the
existing schemas and checkpoint readers. No capability is removed from the
development roadmap. Upgrade, DBSwitch and managed-source Clone require their
own installed evidence before any later graduation. The qualified external-source
Clone remains an alias to the same provider, not an independent Keycloak copy.

Disable both controllers by default (`--lifecycle-enabled=false`, Helm
`lifecycle.enabled: false`). The disabled chart omits every operation/snapshot
resource, status and finalizer permission. It retains a fail-closed admission
policy protecting future approval and child provenance, including while writers
are disabled. Other instance/import/theme permissions belong to their separate
controllers and remain independently reviewable.

When explicitly enabled, an administrator must approve the **exact object UID,
generation, canonical intent (including tenant scope), and source instance UID**.
The controller publishes a bounded `Authorized=False/ApprovalRequired` request.
It creates no execution checkpoint, snapshot capture, child or instance change
before approval. Namespace administrators configured through
`lifecycle.adminGroups` (and `system:masters`) alone may change
`hanko.sh/lifecycle-approval`; the operator cannot approve itself. Ordinary authors
can submit requests. Changing their spec or tenant invalidates prior approval.
Recreating either object never transfers approval.

The registered controller guard reads uncached state and rechecks authority
immediately before child creation, snapshot capture/Job creation and instance
patches. Removing approval suspends further effects; it does not undo an effect
already accepted by Kubernetes or cancel an existing backup Job. Kubernetes does
not provide a transaction across an approval read and a different-object write.
Instance patches additionally retain optimistic resource-version preconditions.

An operation-owned configuration snapshot may use its parent's current approval
only while the exact checkpointed Snapshot step is pending/running. Name, owner
UID, intent annotation, generation, tenant and complete child spec must match.
Admission also protects operation child provenance on instances/imports/snapshots
from ordinary writers; forged owner references are not authority.

DBSwitch reads only a same-namespace, same-tenant-scope, non-deleting dedicated
Secret. Admin, CA and serving-TLS references are refused. The reviewed target
contains exactly `KC_DB=postgres`, `KC_DB_URL` (a bounded PostgreSQL JDBC URL),
`KC_DB_USERNAME` and `KC_DB_PASSWORD`. Arbitrary environment injection is refused.
Secret values never enter approval requests, failure status or logs. Secret
writers remain a separate trusted authority and must be restricted accordingly.
Cross-namespace Clone and `includeData` Clone remain refused.

## Consequences

Before upgrading an installation with pending lifecycle work, suspend submission,
inventory existing requests/children and retain their checkpoints. Enabling the
new writers requires independent protection of approval metadata and an explicit
review of every pre-existing approval; never bulk-approve a namespace. A pending
legacy operation waits for approval; an incomplete legacy checkpoint still fails
closed under the existing recovery rules. Re-enabling resumes only the original
bound intent. Removing approval cannot be described as rollback.

The chart installer needs permission to install the namespace-scoped admission
policy/binding. A raw binary installation must install equivalent independent
admission protection before enabling the flag. Merely allowing authors to write
the approval annotation is not an authorization mechanism.

Any future removal or incompatible experimental change must be announced in
CHANGELOG and the API support inventory at least one public minor release before
removal, with a migration/retirement path preserving journals and child ownership.
There is no removal date and no published predecessor today. A later stable
selection requires a fresh graduation review, installed upgrade/rollback and
production evidence; exclusion does not authorize silent removal.

## Enforcement

- [Controller guard and effect-boundary rechecks](../../../internal/controller/lifecycle_authority.go),
  [adversarial tests](../../../internal/controller/lifecycle_authority_test.go).
- [Independent admission protection](../../../charts/hankoshell-operator/templates/lifecycle-admission.yaml)
  and [real API tests](../../../api/v1alpha1/lifecycle_authority_integration_test.go)
  on the full Kubernetes window.
- [Live RBAC checks](../../../api/v1alpha1/custom_rbac_integration_test.go) and
  [approval patch preparation](../../../tools/operations/lifecycle_approval.py).
- [Installed Clone qualification](../../../tools/qualification/scenarios/system_test.py): explicit
  opt-in, approval wait, independent administrator patch, real RBAC interruption,
  restart and the same durable child UIDs. This remains the bounded Clone case.
- [Graduation records](../../../tools/qualification/config/contracts/stable-graduation.json) and
  [operator procedure](../../secure-deployment.md#experimental-lifecycle-approval).
