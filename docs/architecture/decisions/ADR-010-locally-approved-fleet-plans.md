# ADR-010: Locally approved signed fleet plans

Status: Accepted

## Context

Hub bundle HMAC uses a bearer-token-derived key. Token possession can therefore
forge integrity evidence. Publisher authority needs a separate trust root,
explicit target/source binding and durable replay protection. ADR-002 retains
pull distribution and local execution authority; this decision adds the optional
signed transition without changing Keycloak's native extension boundaries.

## Decision

Use Ed25519 detached signatures over domain-separated exact payload bytes, with
versioned closed JSON and administrator-approved public keys in a protected
ConfigMap. No bearer-derived signing key, remote key discovery, algorithm
negotiation or online verification service is accepted. The
[fleet contract](../fleet-reconciliation.md) compares mechanisms and defines all
bindings, refusal reasons, rotation, replay and disconnected behavior.

The operator deployment selects the trust ConfigMap. The tenant and Hub cannot
choose a replacement trust root. Persist the verified sequence and payload
identity before any content write, and condition subsequent writes on current
source intent, trust identity, checkpoint and validity. Once a signed checkpoint
exists, removing configuration never authorizes legacy HMAC fallback.

## Consequences

Legacy installations remain explicit legacy HMAC consumers until administrators
enable signing. Signed mode requires a Hub endpoint capable of the new media type
and independently provisioned trust; this repository does not implement that Hub.
The high-water mark survives failures and may advance before the whole graph is
applied. Kubernetes writes are not a multi-object transaction. Operator/CRD
downgrades need suspended management and checkpoint preservation.

Current execution derives capability requirements from the finite bundle kinds,
checks qualified provider/native permission evidence and honours independent local
pause/refuse controls. Partial selection is explicit and retains every signature,
tenant and field-ownership guard. Theme builds and realm creation are outside the
current conservative rollout profile. Precompiled theme installation is separately
permitted only with independent local image approval and the existing Keycloak
providers mount; it grants no build authority. Retain immutable signed envelopes,
recover without Hub and reverify local authority immediately before each native mutation.
Strict/sticky expiry and clock regression fence disconnected writes. Rollback is
a new monotonic signed plan bound to reverified historical content and journaled
locally; it never prunes provider objects. Provider portability and installed
fleet qualification remain #75/#80. This does not enable production publication.

## Enforcement

- [Pure verifier](../../../internal/fleetplan/verify.go) and
  [cryptographic/negative tests](../../../internal/fleetplan/verify_test.go).
- [Tenant checkpoint and conditional apply](../../../internal/controller/hankotenant_fleet.go).
- [Offline retention and provider guard](../../../internal/controller/hankotenant_recovery.go),
  [reference verification](../../../internal/fleetplan/recovery.go) and
  [API recovery tests](../../../api/v1alpha1/fleet_recovery_integration_test.go).
- [Bounded HTTPS transport](../../../internal/hub/fleet.go).
- [API checkpoint schema](../../../api/v1alpha1/hankotenant_types.go).
- [Capability selection](../../../internal/fleetplan/rollout.go),
  [provider permission evidence](../../../internal/keycloak/fleet_permissions.go) and
  [rollout API tests](../../../api/v1alpha1/fleet_rollout_integration_test.go).
- [Real HTTPS/API recovery and local trust admission](../../../api/v1alpha1/fleet_plan_integration_test.go).
- [Independent local trust policy](../../../config/security/fleet-plan-trust-admission.yaml).
