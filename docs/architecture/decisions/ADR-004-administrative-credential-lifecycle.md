# ADR-004: Administrative credential authority and recoverable rotation

Status: Accepted

## Context

An administrative client credential exposes all authority granted to that identity.
Kubernetes namespaces and provider ownership markers do not narrow the native
Keycloak role scope. Rotating a credential without durable preparation can leave
Keycloak using a value lost before the corresponding Kubernetes Secret update.

## Decision

Administrators provision dedicated service accounts and only the operation-specific
native grants in the current permission contract. The operator does not repair a
denied call by granting itself privileges. Separate realms, credentials and
instances according to the required trust boundary.

Instance administrative rotation is explicitly enabled with
`spec.rotateAdminCredentials`. When enabled, `HANKO_KC_SA_MAX_AGE` defaults to
90 days. Persist the exact pending credential and rotation ID in the admin Secret
before applying it to Keycloak; authenticate with the pending value before
promotion. Restart recovery probes the persisted value before repeating a write.
A metadata-only audit receipt remains pending until accepted by the configured
Hanko API, independently of the credential mutation. Status exposes the schedule,
not credential values. Disabled rotation leaves the lifecycle administrator-owned
and refuses to resume a pending write silently.

## Consequences

Persist-before-apply makes the administrative rotation resumable. Provider or
audit outages can extend the interval or leave the instance degraded; the age
setting is not a guaranteed maximum exposure window. Rotation requires explicit
native permissions and an audit destination. Shared credentials retain their
shared blast radius. Earlier platform text describing mandatory rotation or broad
role lists is replaced here by the current opt-in and tested permission contract;
this record does not authorize new grants or automatic revocation of old grants.

## Enforcement

- [Rotation state machine](../../../internal/controller/hankokeycloakinstance_rotation.go)
  and [persist, recover, verify and audit tests](../../../internal/controller/hankokeycloakinstance_rotation_test.go).
- [Opt-in refusal tests](../../../internal/controller/hankokeycloakinstance_capabilities_test.go).
- [Metadata-only audit client](../../../internal/hankoapi/audit.go) and
  [audit tests](../../../internal/hankoapi/audit_test.go).
- [Native permissions and rotation operations](../../keycloak-permissions.md).
