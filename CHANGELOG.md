# Changelog

## 1.0.0 — Unreleased

<!-- release-notes:start -->
### Release overview

hankoShell Operator 1.0.0 reconciles application identity and access from
Kubernetes into Keycloak. This initial version is under qualification and has
not been published.

### Features

- Realms, shared authentication policies and upstream identity providers.
- OIDC SPA, web and machine clients, plus a bounded SAML subset.
- Roles, composites, API permissions and organization grants.
- Credential rotation, workload federation and authorized Secret delivery.
- Bounded delegation through the dedicated Keycloak extension.
- Discovery, observation and explicit adoption of existing Keycloak objects.
- Optional signed fleet plans, local pause and reconnect support.
- Precompiled Keycloak theme installation with JAR integrity checks and local image approval.
- Namespace-scoped permissions, provider TLS verification and authenticated metrics.
- Resource-server writes require a current managed application and its exact Keycloak ownership marker.
- Linux AMD64/ARM64 images and Helm installation using immutable image digests.

### Qualification

The project remains in initial development. All 17 `hanko.sh/v1alpha1` resources
use the experimental `v1alpha1` API for both serving and storage.

Publication requires completed endurance, HA qualification and independent
release approval. Advanced lifecycle operations, portable restore, the second
provider and connected integrations retain their documented limitations.

See [remaining work](https://github.com/Alien6-Studio/hankoshell-operator/milestone/11),
[API scope](docs/api-support.md), [support window](docs/support-window.md) and
[qualification](docs/qualification.md).
<!-- release-notes:end -->
