# Changelog

## 0.1.0 — Unreleased

First standalone hankoShell Operator distribution, extracted from the platform
under Apache-2.0. This entry describes the prepared source; no public artifact
or target-cluster qualification is implied by the version number.

### Added

- Required real-Keycloak HTTPS Admin API qualification on digest-pinned 26.8.0
  and 26.7.5: lifecycle, IAM/MFA policy, roles, brokers, credential rotation,
  drift, ownership/finalizers and read-only import. Document exact qualification
  limits and master administration requirements; preserve existing API/versions.
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

### Compatibility and limits

- Retain all 16 CRDs and existing Kubernetes names/selectors. The deprecated
  `HankoEmailProvider` no longer reads vault credentials or sends messages;
  messaging integrations belong to the API and Keycloak retains native SMTP.
- Hub bundles retain HMAC authentication derived from the bearer token, without
  independent publisher authentication. Ed25519 mesh policies use a separate
  trust boundary; their operator projection remains audit-only.
- Backup/restore portability, cloud-specific networking and mesh enforcement
  require installation qualification. Auth0 integration is not implemented.
