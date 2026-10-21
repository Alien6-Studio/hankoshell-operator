# API changes and rollback

Version 1.0.0 is the initial, unpublished version. All 17 resources use
`hanko.sh/v1alpha1` for serving and storage. There is no conversion webhook or
public predecessor to migrate from.

## Schema changes

Prefer additive optional fields. A required field, tighter validation, changed
default, list topology change, rename or removal needs explicit review and
fixtures covering the resulting behavior. Update the development API snapshot
and security inventory only after reviewing the actual difference.

The [Go contract](go-api-contract.md) checks exported types. Native Kubernetes
tests verify admission, typed read-back, status, field ownership and unknown-field
rejection for every CRD. These checks do not establish compatibility with a
hypothetical previous public release.

Helm does not update existing CRDs during an upgrade. Apply the reviewed CRDs
before changing the operator image, and verify that existing resources remain
readable and reconcile correctly. Retain a private backup of the current CRDs,
resources and provider configuration before changing an existing installation.

## Persisted state

Preserve object UIDs, owner references, approval bindings, provider ownership
markers, rotation journals and recovery checkpoints. A controller restart must
resume the recorded intent; clearing status or adding ownership markers to bypass
a refusal is not a migration.

Inspect in-flight operations before changing readers. An older image may not
understand newer checkpoints. Stop affected writers if their authority or pending
state cannot be established. Runtime outputs and external Keycloak effects do not
roll back when the operator image changes.

## Future public versions

After publication, retain authentic schemas and conformance fixtures for each
supported release. Changes then follow the [compatibility policy](compatibility-policy.md).
A second API version will require a demonstrated need, semantic round-trip tests
and a qualified storage transition before it is introduced.
