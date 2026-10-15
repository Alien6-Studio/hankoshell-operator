# ADR-049: Locally approved signed fleet plans

Status: Accepted

## Context

Hub bundle HMAC uses a bearer-token-derived key. Token possession can therefore
forge integrity evidence. Publisher authority needs a separate trust root,
explicit target/source binding and durable replay protection. ADR-010 retains
pull distribution and local execution authority; this decision adds the optional
signed transition without changing Keycloak's native extension boundaries.

## Decision

Use Ed25519 detached signatures over domain-separated exact payload bytes, with
versioned closed JSON and administrator-approved public keys in a protected
ConfigMap. No bearer-derived signing key, remote key discovery, algorithm
negotiation or online verification service is accepted. The
[fleet contract](../fleet-reconciliation.md) compares mechanisms and defines all
bindings, refusal reasons, rotation, replay and future disconnected behavior.

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

Current execution permits the existing finite five bundle kinds and no additional
capability requirements. Provider portability, partial rollout, offline provider
expiry, controlled rollback and installed fleet qualification remain #75 and
#78–#80. Accepting this verification contract does not qualify those behaviors or
enable production publication.

## Enforcement

- [Pure verifier](../../../internal/fleetplan/verify.go) and
  [cryptographic/negative tests](../../../internal/fleetplan/verify_test.go).
- [Tenant checkpoint and conditional apply](../../../internal/controller/hankotenant_fleet.go).
- [Bounded HTTPS transport](../../../internal/hub/fleet.go).
- [API checkpoint schema](../../../api/v1alpha1/hankotenant_types.go).
- [Real HTTPS/API recovery and local trust admission](../../../api/v1alpha1/fleet_plan_integration_test.go).
- [Independent local trust policy](../../../config/security/fleet-plan-trust-admission.yaml).
