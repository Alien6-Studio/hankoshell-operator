# hankoShell Operator

Declare application identity and access in Kubernetes; keep Keycloak in sync.

[![CI](https://github.com/Alien6-Studio/hankoshell-operator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Alien6-Studio/hankoshell-operator/actions/workflows/ci.yml)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/hankoshell-operator)](https://artifacthub.io/packages/search?repo=hankoshell-operator)
[![Version](https://img.shields.io/github/v/release/Alien6-Studio/hankoshell-operator)](https://github.com/Alien6-Studio/hankoshell-operator/releases)
[![Go](https://img.shields.io/badge/go-1.27.3-00ADD8.svg)](go.mod)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.35%E2%80%931.37-326CE5.svg)](docs/support-window.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

hankoShell Operator reconciles realms, application clients, roles, API permissions
and machine credentials from Kubernetes resources. Identity configuration follows
the same Git review and deployment workflow as your applications.

Use it with an existing Keycloak, including one managed by the official Keycloak
operator, or let it provision a provider instance. Standalone use requires neither
hankoShell Hub nor Continuum. [hanko.sh](https://hanko.sh) describes the wider platform.

## Start with your use case

| You want to… | Follow this journey | Outcome |
| --- | --- | --- |
| Add login to an application | [Connect an OIDC client](#1-connect-an-oidc-client) | A client with reviewed callback and logout URLs, managed from Git. |
| Bring an existing client under declarative management | [Adopt existing configuration](#2-adopt-existing-configuration) | Review the live configuration, acquire ownership, then explicitly enable management. |
| Authenticate a backend or worker | [Give a service its own identity](#3-give-a-service-its-own-identity) | A machine client and a Kubernetes Secret with scheduled credential rotation. |

Keycloak handles user login and token issuance. The operator manages only the
fields and objects it owns. Use one writer per provider object; deleting a managed
resource can also delete its Keycloak counterpart. Applications must reload rotated
credentials. The opt-in [authentik adapter](docs/architecture/second-provider.md)
currently covers a limited OIDC registration experiment.

## Install

Check [Releases](https://github.com/Alien6-Studio/hankoshell-operator/releases) for published versions.
Prepare `operator-values.yaml` with a reviewed image digest, Keycloak HTTPS endpoint,
a dedicated credential Secret, private CA if needed, and exact API/provider egress.
Authorize output Secret and managed Deployment names through `sensitiveWrites`.

Follow the [chart configuration](charts/hankoshell-operator/README.md),
[Keycloak permission model](docs/keycloak-permissions.md) and
[installation guide](docs/secure-deployment.md#configure-an-installation) first.
Install the versioned OCI chart:

```sh
helm upgrade --install hankoshell-operator \
  oci://ghcr.io/alien6-studio/charts/hankoshell-operator --version 1.0.0 \
  --namespace auth --create-namespace \
  --values operator-values.yaml --wait --timeout 5m
```

For a source checkout, use `./charts/hankoshell-operator` instead of the OCI reference
and omit `--version`. The operator watches its release namespace.
Helm installs CRDs on first installation but does not upgrade them: use the
[API migration policy](docs/api-migration-policy.md) before applying reviewed CRD
changes to an existing installation. Metrics are off by default; [enabling them requires mTLS](docs/operations-runbooks.md#secure-metrics).

## 1. Connect an OIDC client

Your SPA needs user login through Keycloak. These examples use the operator's
`auth` namespace and an existing realm named `example`; replace the URLs and names
with your own. Save this as `portal-identity.yaml`:

```yaml
apiVersion: hanko.sh/v1alpha1
kind: HankoApplication
metadata:
  name: customer-portal
  namespace: auth
spec:
  realmRef: example
  clientID: customer-portal
  mode: Manage
  protocol: oidc
  type: spa
  redirectURIs:
    - https://portal.example.com/callback
  postLogoutRedirectURIs:
    - https://portal.example.com/
```

```sh
kubectl apply -f portal-identity.yaml
kubectl get hankoapplication customer-portal --namespace auth
```

Once reconciliation succeeds, Keycloak contains the `customer-portal` public
client with those callback and logout URLs. Your SPA uses it in its OIDC login
flow; later Git changes update the declared configuration. For server-side web
clients, SAML and runtime bindings, see the [application guide](docs/architecture/application-identity.md).

## 2. Adopt existing configuration

Your application already authenticates through Keycloak. Start with its actual
settings in `Observe` mode. Configure the read-only `inventory-keycloak` source
using the [adoption guide](docs/architecture/existing-keycloak-adoption.md#administrator-workflow),
then save a matching declaration as `existing-portal.yaml`:

```yaml
apiVersion: hanko.sh/v1alpha1
kind: HankoApplication
metadata:
  name: existing-portal
  namespace: auth
  annotations:
    hanko.sh/adoption-source: inventory-keycloak
spec:
  realmRef: example
  clientID: existing-portal
  mode: Observe
  type: spa
  redirectURIs:
    - https://existing.example.com/callback
```

```sh
kubectl apply -f existing-portal.yaml
kubectl get hankoapplication existing-portal --namespace auth \
  -o jsonpath='{.status.adoptionCandidate}{"\n"}'
```

Review the candidate's diff, identity and findings. The operator leaves the client
unchanged in Observe. Follow the guide to approve that exact candidate and wait
for a `Verified` adoption receipt. Acquisition preserves the client UUID and
configuration; switching to `Manage` is a separate, explicit action. Existing
unmarked or foreign-owned clients are never claimed just because their names match.

## 3. Give a service its own identity

Your backend or scheduled worker needs tokens without a user session. Authorize
the exact output Secret `hanko-sa-report-worker` in your installation's
`sensitiveWrites.secrets`, then save this as `worker-identity.yaml`:

```yaml
apiVersion: hanko.sh/v1alpha1
kind: HankoServiceAccount
metadata:
  name: report-worker
  namespace: auth
spec:
  realmRef: example
  clientID: report-worker
  authentication:
    mode: Secret
  secretRotationPolicy:
    enabled: true
    intervalDays: 30
```

```sh
kubectl apply -f worker-identity.yaml
kubectl get hankoserviceaccount report-worker --namespace auth
```

Once Ready, the worker can use OAuth `client_credentials` with client ID
`report-worker` and the `client_secret` key from the owned Secret. Configure its
access separately through roles and API permissions. The application must reload
rotated credentials. For secretless Kubernetes authentication and its prerequisites,
follow the [workload identity guide](docs/architecture/workload-identity.md).

## Status

All 17 resources use one experimental API: `hanko.sh/v1alpha1`. The API remains
in **initial development**; the operator's `1.0.0` version does not graduate it.

[Endurance](https://github.com/Alien6-Studio/hankoshell-operator/issues/95) and
[HA/recovery](https://github.com/Alien6-Studio/hankoshell-operator/issues/96) are complete;
each published delivery requires final-candidate and independent release verification.
Managed Upgrade, Clone and DBSwitch remain
experimental and disabled by default. Track [remaining work](https://github.com/Alien6-Studio/hankoshell-operator/milestone/11)
and [qualification](docs/qualification.md); passing source checks alone does not
establish production compatibility.

<!-- support-window:start -->
| Component | Exact qualification versions | Default |
| --- | --- | --- |
| kubernetes | `1.35.0`, `1.36.2`, `1.37.0` | `1.37.0` |
| keycloak | `26.7.5`, `26.8.1` | `26.8.1` |
<!-- support-window:end -->

Keycloak upgrades are not tied to this exact patch list. Fleet rollout accepts
stable `26.x`; workload federation starts at `26.7.5`, and discovery overrides at
`26.8.0`. Native capability, permission and read-back checks still apply.

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
