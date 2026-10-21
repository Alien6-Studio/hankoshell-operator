# hankoShell Operator

Declare application identity and access in Kubernetes; keep Keycloak in sync.

[![CI](https://github.com/Alien6-Studio/hankoshell-operator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Alien6-Studio/hankoshell-operator/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.0.0--rc.1%20qualification-blue.svg)](#status)
[![Go](https://img.shields.io/badge/go-1.27.3-00ADD8.svg)](go.mod)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.35%E2%80%931.37-326CE5.svg)](docs/support-window.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

hankoShell Operator reconciles realms, application clients, roles, API permissions
and machine credentials from Kubernetes resources. Identity configuration follows
the same Git review and deployment workflow as your applications.

Use it with an existing Keycloak, including one managed by the official Keycloak
operator, or let it provision a provider instance. Standalone use requires neither
hankoShell Hub nor Continuum. [hanko.sh](https://hanko.sh) describes the wider platform.

## What it does

- **Application login:** OIDC SPA, web and machine clients, plus a bounded SAML subset.
- **Access control:** roles, composites, organization grants and API permissions.
- **Shared policies:** MFA, password rules, sessions and upstream identity providers.
- **Machine identity:** credential rotation, workload federation and authorized Secret delivery.
- **Existing installations:** observe and import supported configuration before explicitly adopting it.

Keycloak handles user login and token issuance. The operator manages only the
fields and objects it owns. Use one writer per provider object; deleting a managed
resource can also delete its Keycloak counterpart. Applications must reload rotated
credentials. The opt-in [authentik adapter](docs/architecture/second-provider.md)
currently covers a limited OIDC registration experiment.

## Install from source

The current candidate is **`1.0.0-rc.1`**. Public chart/image artifacts are pending.
Prepare `operator-values.yaml` with a reviewed image digest, Keycloak HTTPS endpoint,
a dedicated credential Secret, private CA if needed, and exact API/provider egress.
Authorize output Secret and managed Deployment names through `sensitiveWrites`.

Follow the [chart configuration](charts/hankoshell-operator/README.md),
[Keycloak permission model](docs/keycloak-permissions.md) and
[installation guide](docs/secure-deployment.md#configure-an-installation) first.
Then, from this checkout:

```sh
kubectl apply -f charts/hankoshell-operator/crds/
helm upgrade --install hankoshell-operator ./charts/hankoshell-operator \
  --namespace auth --create-namespace \
  --values operator-values.yaml --wait --timeout 5m
```

The operator watches its release namespace. Helm does not upgrade CRDs: use the
[storage migration runbook](docs/storage-migration.md) before updating an existing
installation. Metrics are off by default; [enabling them requires mTLS](docs/operations-runbooks.md#secure-metrics).

## Declare an application

After installation, save this as `portal-identity.yaml`. Creating a realm requires
an explicitly authorized provider credential; see the permission model above.

```yaml
apiVersion: hanko.sh/v1alpha1
kind: HankoRealm
metadata:
  name: example
  namespace: auth
spec:
  displayName: Example
---
apiVersion: hanko.sh/v1alpha1
kind: HankoApplication
metadata:
  name: customer-portal
  namespace: auth
spec:
  realmRef: example
  clientID: customer-portal
  type: spa
  redirectURIs:
    - https://portal.example.com/callback
  postLogoutRedirectURIs:
    - https://portal.example.com/
```

```sh
kubectl apply -f portal-identity.yaml
kubectl get hankorealm,hankoapplication --namespace auth
```

Replace the URLs with your own. Your SPA still implements its OIDC login flow.
See the [application guide](docs/architecture/application-identity.md) for web,
machine and SAML clients, runtime bindings and migration.

## Status

This project remains in **initial development**. All 17 `hanko.sh/v1alpha1`
resources are experimental. Candidate `v1beta1` serves Application, Role and
ResourceServer with identical schemas; storage remains `v1alpha1`.

The RC1 is under qualification. Stable 1.0 requires completed endurance, HA and
independent release verification. Managed Upgrade, Clone and DBSwitch remain
experimental and disabled by default. Track [remaining work](https://github.com/Alien6-Studio/hankoshell-operator/milestone/11)
and [qualification](docs/qualification.md); passing source checks alone does not
establish production compatibility.

<!-- support-window:start -->
| Component | Exact qualification versions | Default |
| --- | --- | --- |
| kubernetes | `1.35.0`, `1.36.2`, `1.37.0` | `1.37.0` |
| keycloak | `26.7.5`, `26.8.0` | `26.8.0` |
<!-- support-window:end -->

See the [support window](docs/support-window.md),
[compatibility policy](docs/compatibility-policy.md), [API contract](docs/api-support.md),
[graduation criteria](docs/stable-graduation.md) and
[provider review](docs/stable-provider-review.md) for exact scope and limitations.

## Develop and contribute

Use Go 1.27.3, Python 3.12+, Helm and the pinned tools in [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
python3 -m pip install -r tools/requirements.txt
make install-tools
make qualify
make build
```

Docker is required for real Keycloak and installed-cluster scenarios.
[Qualification commands](docs/qualification.md) describe the available profiles.

[Documentation](docs/README.md) · [Architecture decisions](docs/architecture/decisions/README.md) ·
[Changelog](CHANGELOG.md) · [Report an issue](https://github.com/Alien6-Studio/hankoshell-operator/issues) ·
[Security](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md)

Licensed under [Apache-2.0](LICENSE). Distributed dependency attributions are in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) and [THIRD_PARTY_NOTICES.cosign](THIRD_PARTY_NOTICES.cosign).
