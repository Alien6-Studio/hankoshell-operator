# Changelog

## Unreleased

## 1.0.1

<!-- release-notes:start -->
### Release overview

hankoShell Operator 1.0.1 updates the embedded image verifier and improves the
standalone onboarding path. The 17 `hanko.sh/v1alpha1` APIs remain experimental;
this patch does not change their schema or enable lifecycle operations.

### Security

- Update embedded Cosign to 3.1.4 and chi to 5.4.0, addressing CVE-2026-114437.
- Use maintained OpenPGP dependencies instead of the deprecated
  `golang.org/x/crypto/openpgp` packages reported by GO-2026-5932. The module-level
  UNKNOWN report can remain in scanners; this is not a claim of an empty report.
- Reject verifier builds that downgrade Cosign or reintroduce those packages.

### Onboarding

- Add a disposable kind demonstration for OIDC registration, explicit adoption
  with a preserved client UUID, and real machine authentication.
- Verify callback changes against the current declared generation and the actual
  Keycloak client, with isolated kubeconfig and owned-cluster cleanup.
- Organize the README around three usage journeys and publish the qualification
  measurements with their limits.
- Align documentation with the public release and the 17-resource API inventory.

See the [standalone chart guide](charts/hankoshell-operator/README.md),
[API scope](docs/api-support.md), [support window](docs/support-window.md) and
[qualification](docs/qualification.md). Historical endurance results retain their
recorded revisions; the patch has its own final-image qualification.
<!-- release-notes:end -->

## 1.0.0


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
