# Changelog

## 0.1.0 — Unreleased

First standalone hankoShell Operator distribution, licensed under Apache-2.0.

<!-- release-notes:start -->
### Release overview

hankoShell Operator 0.1.0 reconciles declarative Keycloak IAM configuration from
Kubernetes. Application login clients, redirect URLs, token claims, roles and
machine identities can be reviewed alongside deployment manifests. Reconciliation
updates the supported fields/resources under the operator's ownership; observation
and import allow administrators to review existing configuration before adoption.
Hub, hankoShell API and Continuum fleet integrations are optional for this use case.
Project: https://hanko.sh.

Capabilities include realms, reusable IAM/MFA policies, application and client
roles, identity providers/mappers, resource-server configuration, service accounts
and client-secret rotation. Keycloak still performs login, token issuance and
authentication email delivery. The operator is not a general user-provisioning tool.

Qualification covers Linux Kubernetes **1.35–1.37**, using API-server/etcd fixtures
**1.35.0, 1.36.2 and 1.37.0** for all 16 CRDs, server-side apply, RBAC and Restricted
admission. Real HTTPS Keycloak Admin API v1 tests cover **26.8.0 and 26.7.5**,
including reconciliation, least-privilege identities, denied operations and
ownership/finalizers. Other Keycloak patches/major lines and Kubernetes minors
are unqualified. This is not cloud, node, CNI/CSI, browser-login or production
database qualification.

Administrative transport requires verified HTTPS by default. Intentionally
trusted HTTP requires an explicit standard-profile acknowledgement; enterprise
remains HTTPS-only. Use a dedicated credential with the documented target-realm
permissions, namespace-scoped RBAC, non-root Restricted pod settings and explicit
default-deny networking. Credentials stay in referenced Secrets. Metrics are
disabled by default; enabled metrics use plaintext HTTP with constrained ingress.
Hub bundles use token-derived HMAC, not an independent publisher signature.
Mesh policy projection is audit-only, not workload enforcement.
Hub self-updates require a local digest/version/source approval and verified
publisher signature. Decommission authorization expires at its deadline.
Instance master hardening, administrative credential rotation and adopted
Service discovery writes require explicit spec opt-ins.
Managed instances require an explicit serving TLS Secret and expose native
HTTPS/8443. HTTP requires both process and instance acknowledgements in standard
profile; enterprise rejects it. Optimized images must include root-context health
endpoints; the separate HTTP/9000 health listener has no Service or pod ingress.
Database snapshots require an explicitly approved and publisher-verified image
digest plus a dedicated backup Secret; the Job receives only selected libpq keys.
Backup images need their own security review and database recovery qualification.

Install the reviewed source chart, or the published
`oci://ghcr.io/alien6-studio/charts/hankoshell-operator` chart at version `0.1.0`
when available, following the [secure deployment guide](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md)
and [permission model](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/keycloak-permissions.md).
Published chart values select the scanned multi-architecture image digest.
Source govulncheck and final-image scans (including embedded cosign) are additive;
fixable HIGH/CRITICAL findings block delivery. BuildKit SBOM/provenance, Sigstore
signatures and signed/timestamped Continuum Attest delivery bindings have distinct
purposes; none guarantees absence of vulnerabilities.

**0.1.0 is a normal SemVer release in initial development, not a prerelease.**
The `hanko.sh/v1alpha1` APIs are experimental and may change across minor versions
before 1.0. Portable backup/restore is not qualified; snapshots, clones and
database-reference switches are not a tested disaster-recovery path. Rolling back
the operator does not undo provider deletion, credential rotation or CRD changes.
Deployment-specific image admission, database recovery and enterprise integration
require administrator qualification. Report vulnerabilities privately through
[GitHub security advisories](https://github.com/Alien6-Studio/hankoshell-operator/security/advisories/new);
response targets and supported versions are in SECURITY.md.
<!-- release-notes:end -->

### Added

- Shared release packaging contract and a required nonpublishing rehearsal using
  the exact scanned OCI archive, curated notes, checksums, local cosign signature
  and native signed/timestamped/recomputed Continuum Attest fixture evidence.
  Production signer/TSA, GitHub OIDC, registry publication and Artifact Hub
  ownership remain separate launch requirements.
- Align documentation, CRD descriptions and catalog metadata with normal 0.1.0
  initial-development releases and experimental v1alpha1 APIs. Explain lifecycle
  and privileged-operation limits; replace the misleading Helm signKey annotation
  with an explicitly named Attest delivery verification-key link.
- Honor the existing `leaderElect: false` chart setting by passing an explicit
  boolean manager flag; default election remains enabled. Reject non-boolean values.

- Tested Keycloak administrative permission contract for existing realms, optional
  features and read-only import/observation, with required positive and denied
  operations on real 26.8.0/26.7.5 service accounts and a complete API inventory.
  Record version-dependent server disclosure and 26.7.5 view-client secret access.

- Required real-Keycloak HTTPS Admin API qualification on digest-pinned 26.8.0
  and 26.7.5: lifecycle, IAM/MFA policy, roles, brokers, credential rotation,
  drift, ownership/finalizers and read-only import. Document exact qualification
  limits and scoped administration requirements; preserve existing API/versions.
- Declarative Keycloak realms, applications, roles, reusable IAM profiles,
  service accounts and resource servers using the existing `hanko.sh/v1alpha1` API.
- External, managed and adopted provider modes; the official Keycloak operator
  remains optional.
- Optional hankoShell API organization projection, supervision and Hub fleet
  enrollment, synchronization and credential rotation.
- Standard and enterprise installation profiles, private Continuum Hub
  transport, baseline NetworkPolicy and optional Cilium policies.
- Helm packaging, Linux AMD64/ARM64 image builds, Sigstore signing and
  mandatory Continuum Attest delivery verification in the release workflow.
- Artifact Hub chart annotations, icon and OCI repository metadata publication.
- Security policy, code of conduct and secure deployment/trust documentation.

### Security

- Remove the mutable default database snapshot image and broad DB Secret import.
  Require an explicit `backupImage` digest/source/publisher approval scoped to
  `database-backup`, live signature verification and a separate `backupSecretRef`.
  Recheck approval/key revocation after all workload signature checks. Harden
  backup pods with read-only root, RuntimeDefault seccomp and no Kubernetes token;
  reject foreign/legacy/altered Jobs instead of trusting their name or completion.
  Qualify schema, real Kubernetes Job round-trip and Restricted pod admission.

- Make metrics disabled by default across the binary and Helm listener, port,
  Service, discovery and ingress. Separate optional ServiceMonitor discovery,
  require exact Prometheus namespace/pod selectors with baseline NetworkPolicy,
  and admit only their conjunction on TCP/8080. Reject invalid/broad configuration
  and verify the contract with Helm, controller-runtime and real Kubernetes APIs.

- Require a checksum-pinned Trivy gate on both final OCI runtime platforms,
  including cosign's versioned main module, dependencies, Go runtime and OS
  inventory. Block fixable HIGH/CRITICAL vulnerabilities and validate scoped,
  expiring HIGH exceptions; retain complete reports and fresh database identity.
- Build/export once, verify and copy the scanned OCI graph without rebuilding;
  defer the release image tag until signatures and Continuum Attest verification
  pass. Pin the scanned digest in the delivered chart and bind reports/policy
  in signed checksums and the receipt.
- Build cosign as a versioned dependency for scanner visibility and update its
  crypto dependency to v0.56.0 after image scanning identified fixable findings.

- Require verified HTTPS by default for administrative Keycloak connections,
  including instance, tenant and rotation paths. Require explicit standard-only
  HTTP acknowledgement, retain HTTPS-only enterprise, validate endpoint forms
  consistently in Helm/Go and keep certificate verification enabled.

- Remove operator self-grants of master proxy roles, including impersonation;
  require administrator-provisioned target access and let Keycloak own proxy
  lifecycle. Verify the three-role common profile without global administrator
  privileges; document native creator grants and optional master authority.
- Reject unreviewed Keycloak HTTP methods/routes at a common permission gateway;
  refuse redirects, require inventory updates and reject network-call bypasses
  in regression tests.

- Qualify Kubernetes 1.35–1.37 with real API-server/etcd tests of all 16 CRDs,
  server-side apply, CEL, status, RBAC and Restricted admission. Require every
  matrix result before merge or Attest delivery; reject unqualified cluster minors.
- Schedule the operator on Linux nodes and add optional RuntimeDefault AppArmor
  and stable user namespaces (>=1.36), preserving the mandatory baseline.
- Bound Hub bundle and mesh-policy responses to 1 MiB, control responses to
  64 KiB, and error responses to 8 KiB; propagate body-read errors and discard
  partially decoded heartbeat commands.
- Enforce verified TLS 1.3 and reviewed destinations in the enterprise profile,
  with controlled public bootstrap and no implicit public synchronization fallback.
- Keep signing and policy-administration privileges outside the operator;
  require reviewed admission controls for workload-image policy changes.
- Install and verify the pinned golangci-lint v2.14.0 independently of the PATH.

### Fixed

- Align managed Keycloak listener, serving certificate, Service, probes and
  ingress policy with the HTTPS administrative transport contract. Validate TLS
  configuration before infrastructure changes; refuse implicit HTTP and mismatched
  serving certificates. Use optimized startup with the read-only image filesystem.
  Advertise the validated AdminRef endpoint to API discovery without a scheme
  downgrade or a hostname change.
- Require independent local release approval and publisher verification before
  Hub self-updates, including already-pinned images; reject stale Deployment
  patches after concurrent administrator changes.
- Reject expired/malformed decommission commands and stop further cleanup or
  confirmation when their execution deadline is reached.
- Limit instance administrative writes to explicitly requested master hardening,
  AdminRef rotation and adopted Service discovery. Existing resources default
  to external administration; requested hardening failures cannot report Ready.

- Accept bounded native authorization creation representations when Keycloak
  omits Location, and the successful 201 response to authorization updates.

### Compatibility and limits

- `metrics.enabled` is now the global switch; existing ServiceMonitor users must
  also set `metrics.serviceMonitor.enabled` and configure Prometheus identity and
  discovery labels. Disabled metrics remove the old always-on listener/Service.
  Metrics remain unauthenticated HTTP; NetworkPolicy requires a supporting CNI
  and does not encrypt traffic. Review prior exposure/defaults before rollback.

- Existing HTTP Keycloak values now fail closed unless administrators explicitly
  set `keycloak.allowInsecureHTTP: true`; prefer migrating to verified HTTPS.
  Default chart endpoint/egress changes to HTTPS/8443. Public CA endpoints need
  no CA Secret; private CA configuration remains supported.

- The deprecated `HankoEmailProvider` no longer reads vault credentials or sends
  messages;
  messaging integrations belong to the API and Keycloak retains native SMTP.
- Hub bundles retain HMAC authentication derived from the bearer token, without
  independent publisher authentication. Ed25519 mesh policies use a separate
  trust boundary; their operator projection remains audit-only.
- Backup/restore portability, cloud-specific networking and mesh enforcement
  require installation qualification. Auth0 integration is not implemented.
