# ADR-010: Optional Hub pull distribution and bounded supervision

Status: Accepted

## Context

Remote clusters may have no inbound control-plane connectivity. Fleet distribution
and health reporting need an operator-initiated protocol without coupling the
operator's Go module to the platform implementation or making Hub mandatory for
standalone IAM reconciliation.

## Decision

HankoTenant pulls bundles using its enrolled cluster identity, checks the current
HMAC integrity contract before applying child CRs, and reports bounded supervision
data. The Hub HTTP client depends only on the supervision DTO among project
packages. Decommission and self-update report through that client; reconcilers
retain local tenant ownership, field ownership and workload authority checks.

Hub commands cannot provide image trust roots or replace local operator-update
approvals; [ADR-047](ADR-047-signed-workload-approvals.md) governs that boundary.
Hub and platform API/Continuum integrations remain optional. A tenant's dedicated
Keycloak routing is established independently of successful Hub synchronization.

## Consequences

Pull delivery works without inbound cluster access but introduces polling latency
and synchronization failures. Response sizes and timeouts are bounded; partial
responses cannot deliver commands. A token-derived HMAC is shared-secret integrity,
not independent publisher identity or replay resistance. Multi-object apply can
partially succeed. Signed fleet plans, disconnected validity and rollback still
require the work tracked in the deployment guide; this record does not assert
those guarantees from the existing bundle protocol. [ADR-049](ADR-049-locally-approved-fleet-plans.md)
now adds opt-in independent publisher verification and a persistent anti-replay
checkpoint. It supersedes the HMAC authentication decision for signed-mode
tenants; disconnected execution and controlled rollback remain separate work.

## Enforcement

- [Hub client](../../../internal/hub/client.go),
  [HMAC tests](../../../internal/hub/bundle_signature_test.go) and
  [response budget tests](../../../internal/hub/client_limits_test.go).
- [Tenant reconciler](../../../internal/controller/hankotenant_controller.go) and
  [bundle ownership tests](../../../internal/controller/hankotenant_bundle_test.go).
- [Supervision](../../../internal/supervision/supervision.go) and
  [wire tests](../../../internal/supervision/supervision_wire_test.go).
- [Dependency rules](../../../.go-arch-lint.yml) and
  [current synchronization limits](../../secure-deployment.md).
