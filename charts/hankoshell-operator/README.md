# hankoShell Operator chart

Manage Keycloak realms, applications, roles and API permissions from Kubernetes.
Standalone installations need neither hankoShell Hub nor Continuum.

Version `1.0.0` remains in **initial development** and has not been published. All 17 `hanko.sh/v1alpha1` CRDs are
experimental and use `v1alpha1` for both serving and storage. See the [API inventory](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/api-support.md)
and [selected 1.0 contract](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/public-contract-selection.md).

## Install

Prepare `operator-values.yaml` using the commented [values.yaml](values.yaml)
and the [installation guide](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#configure-an-installation).
You need a reviewed operator image digest, a Keycloak HTTPS endpoint, a dedicated
credential Secret and exact Kubernetes API/provider egress destinations.
Use the [Keycloak permission model](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/keycloak-permissions.md)
to provision that credential. Keep credentials outside committed values.

From a source checkout:

```sh
helm upgrade --install hankoshell-operator ./charts/hankoshell-operator \
  --namespace auth --create-namespace \
  --values operator-values.yaml --wait --timeout 5m
```

The operator watches its release namespace. Helm installs the CRDs on first
installation but **does not upgrade them**. Before updating an existing
installation, follow the [API migration policy](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/api-migration-policy.md).

## Configuration

| Values | Purpose |
| --- | --- |
| `image` | Operator repository, immutable digest and pull policy |
| `keycloak` | HTTPS endpoint, credential Secret and optional private CA |
| `sensitiveWrites` | Exact output Secret and managed Deployment names; empty defaults authorize no creation |
| `networkPolicy` | Exact API/provider egress; supply actual addresses, selectors and ports |
| `replicaCount`, `leaderElect` | Replicas and leader election; keep election enabled for shared reconciliation |
| `reconciliation` | Shared provider budget with 1–8 workers per supported IAM controller; default 1 |
| `metrics` | Opt-in metrics with mandatory mutual TLS; see the [metrics guide](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/operations-runbooks.md#secure-metrics) |
| `hardening` | Optional AppArmor and user namespaces; baseline pod protections always apply |
| `hub`, `continuum` | Optional connected integrations and enterprise transport |
| `lifecycle`, `experimental` | Opt-in experimental capabilities |

`values.schema.json` validates common parameter types and bounds. Templates also
validate cross-field permissions, transport and security requirements. Configure
optional features using the [secure deployment guide](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md).
User namespaces additionally require Kubernetes >=1.36 and compatible Linux nodes
and runtimes. Controller concurrency is not a measured capacity recommendation.

## Compatibility

Exact qualification fixtures are listed below. Install current provider security
patches and review the [support window](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/support-window.md)
and [compatibility policy](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/compatibility-policy.md)
for the scope and limits of these results.

<!-- support-window:start -->
| Component | Exact qualification versions | Default |
| --- | --- | --- |
| kubernetes | `1.35.0`, `1.36.2`, `1.37.0` | `1.37.0` |
| keycloak | `26.7.5`, `26.8.0` | `26.8.0` |
<!-- support-window:end -->
