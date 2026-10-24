# Changelog

## Unreleased

- Add a disposable kind demonstration for OIDC registration, reviewed adoption
  of an existing client and machine authentication.
- Align documentation with the public 1.0.0 release and its 17 experimental
  CRDs; distinguish API graduation and historical upgrade evidence from publication.
- Update the embedded Cosign verifier to 3.1.4 and chi to 5.4.0
  (CVE-2026-114437). The updated Rekor dependency uses maintained OpenPGP
  packages instead of the deprecated `golang.org/x/crypto/openpgp` packages
  reported by GO-2026-5932.
- Reject verifier builds that silently downgrade Cosign or reintroduce the
  deprecated OpenPGP packages.

## 1.0.0

<!-- release-notes:start -->
### Release overview

hankoShell Operator 1.0.0 reconciles application identity and access from
Kubernetes into Keycloak. This is the initial operator delivery, with an
experimental `v1alpha1` API.

### Features

- Realms, shared authentication policies and upstream identity providers.
- OIDC SPA, web and machine clients, plus a bounded SAML subset.
- Roles, composites, API permissions and organization grants.
- Credential rotation, workload federation and authorized Secret delivery.
- Bounded delegation through the dedicated Keycloak extension.
- Feature-based Keycloak version eligibility across stable 26.x upgrades, with
  exact tested patches recorded separately and native safety checks preserved.
- Discovery, observation and explicit adoption of existing Keycloak objects.
- Optional signed fleet plans, local pause and reconnect support.
- Precompiled Keycloak theme installation with JAR integrity checks and local image approval.
- Namespace-scoped permissions, provider TLS verification and authenticated metrics.
- Resource-server writes require a current managed application and its exact Keycloak ownership marker.
- Linux AMD64/ARM64 images and Helm installation using immutable image digests.

### Qualification

The API remains in initial development. All 17 `hanko.sh/v1alpha1` resources
use the experimental `v1alpha1` API for both serving and storage.

Endurance and HA/recovery qualification are complete for their recorded scope.
Publication also requires final-candidate qualification and independent
release approval. The current provider window includes the Keycloak 26.8.1
security patch; existing 26.8.0 workload declarations remain readable.
Advanced lifecycle operations, portable restore, the second
provider and connected integrations retain their documented limitations.

See [remaining work](https://github.com/Alien6-Studio/hankoshell-operator/milestone/11),
[API scope](docs/api-support.md), [support window](docs/support-window.md) and
[qualification](docs/qualification.md).
<!-- release-notes:end -->
