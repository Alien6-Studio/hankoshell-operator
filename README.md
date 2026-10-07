# hankoShell Operator

Manage Keycloak alongside the applications that depend on it.

hankoShell Operator turns your application's identity requirements into Keycloak
configuration: its login client, redirect URLs, roles, token claims and machine
credentials. Declare the desired configuration in Kubernetes, review it in Git,
and let the operator keep the fields it manages in sync with Keycloak.

Platform teams can reuse authentication policies across realms, connect upstream
identity providers and rotate client secrets. Application teams can keep their
login and access configuration with their deployment manifests. It works with
an existing Keycloak instance, including one managed by the official Keycloak
operator, and can also provision a Keycloak Deployment.

**[What it manages](#what-it-manages-in-keycloak)** · [First application](#declare-your-first-realm) ·
[Deployment](#deployment) ·
[Secure deployment and trust model](docs/secure-deployment.md) ·
[Changes](CHANGELOG.md)

[![CI](https://github.com/Alien6-Studio/hankoshell-operator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Alien6-Studio/hankoshell-operator/actions/workflows/ci.yml)
[![Release preparation](https://img.shields.io/badge/release-0.1.0%20in%20preparation-blue.svg)](CHANGELOG.md)
[![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.35%E2%80%931.37-326CE5.svg)](docs/secure-deployment.md#kubernetes-compatibility-and-hardening)
[![Delivery](https://img.shields.io/badge/delivery-Continuum%20Attest-blue.svg)](#verified-delivery)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Why use it?

- **Onboard applications with their identity configuration.** A new web app or
  service can declare its Keycloak client, allowed callbacks and roles alongside
  its Kubernetes deployment in the same reviewable change.
- **Review identity changes before applying them.** Redirect URLs, role mappings
  and authentication policies can follow your existing pull request and GitOps
  workflow. The operator periodically reconciles the fields under its ownership,
  correcting drift in managed configuration.
- **Reuse security policies.** Define MFA, password rules, session durations and
  brute-force protection in a shared IAM profile, then reference it from the
  realms that need that policy.
- **Keep machine credentials current.** Configure rotation for confidential
  clients and service accounts; the operator updates their Kubernetes Secrets.
  Applications still need to reload or restart when their credentials change.
- **Start with the Keycloak you already run.** Import supported configuration
  into Kubernetes resources in observation mode, review it, and choose which
  objects the operator will own.

For example, a customer portal can declare its login callbacks and `viewer`
role, while a background worker declares its own machine identity and rotation
schedule. Both use the realm's authentication policy. Your deployment tooling
applies those declarations; hankoShell reconciles the corresponding Keycloak
objects and reports their status in Kubernetes.

## What it manages in Keycloak

| Keycloak configuration | What you can declare |
| --- | --- |
| Realms and login experience | Realm display name, public frontend URL, login theme and realm roles. |
| Application clients | SPA, web and machine clients; login/logout redirect URLs, client roles, realm-role scopes and client attributes. |
| Authentication policies | Reusable MFA, password, session, brute-force, email-verification and authentication-event settings. |
| Identity brokering | Upstream identity providers and their Keycloak mappers, with provider credentials referenced from Secrets. Application mappings can turn upstream OIDC claims into roles or user attributes. |
| Token contents | Client-specific claims from user attributes or fixed values, with control over the declared realm roles included in application tokens. |
| Roles and API permissions | Realm and client roles, composite realm roles, and resource-server scopes, resources and permissions for role or workload principals. |
| Machine credentials | Service-account clients, confidential client secrets, scheduled or requested rotation, and explicitly authorized application Secret projections. |
| Existing configuration | Import reports and supported realm, client, service-account and identity-provider configuration; observe existing objects before taking ownership. |

Use one writer for each managed Keycloak object. Observation mode does not
modify provider objects or read their client secrets; management mode owns their
supported lifecycle. General user provisioning and LDAP synchronization are not
exposed as dedicated resources. Keycloak remains responsible for user login,
token issuance and its authentication emails.

<details>
<summary>Custom resource reference</summary>

| Area | Custom resources |
| --- | --- |
| Identity and access | `HankoRealm`, `HankoApplication`, `HankoRole`, `HankoIAMProfile`, `HankoServiceAccount`, `HankoResourceServer` |
| Provider instances and imports | `HankoKeycloakInstance`, `HankoImport` |
| Platform and fleet integration | `HankoOrganization`, `HankoIssuer`, `HankoTenant`, `HankoMeshService` |
| Workload operations | `HankoTheme`, `HankoSnapshot`, `HankoOperation` |

All 16 `hanko.sh/v1alpha1` CRDs are retained, including the deprecated
`HankoEmailProvider`. See the [API definitions](api/v1alpha1) for supported fields.
Integration flags configure clients and do not disable controller registration.
Snapshot data backup still uses installation-specific PostgreSQL/PVC
configuration; portable backup and restore are not qualified.

</details>

## Choose your path

| Your goal | Start here |
| --- | --- |
| Configure login for an application | [Deployment](#deployment) → [Realm and application example](#declare-your-first-realm) |
| Reuse an authentication policy across realms | [IAM profile fields](api/v1alpha1/hankoiamprofile_types.go) → [authentication policy fields](api/v1alpha1/hankorealm_types.go) |
| Import an existing Keycloak configuration | [Import options](api/v1alpha1/hankoimport_types.go) → [provider ownership](#choose-provider-ownership) |
| Coexist with the official Keycloak operator | [Provider ownership](#choose-provider-ownership) |
| Connect a cluster to hankoShell API and Hub | [Platform integrations](#platform-integrations) → [chart configuration](charts/hankoshell-operator/README.md) |
| Use private Hub synchronization through Continuum | [Enterprise profile](docs/secure-deployment.md#enterprise-profile) |
| Review trust, privileges and network controls | [Secure deployment](docs/secure-deployment.md) → [security policy](SECURITY.md) |
| Build or contribute | [Development](#development) → [contributing](CONTRIBUTING.md) |

## Deployment

The chart targets Kubernetes **1.35–1.37** on Linux nodes. Required CI checks
qualify all 16 CRDs, server-side apply, namespace/credential RBAC boundaries and
Restricted Pod Security admission against each minor version. Optional AppArmor
and stable user namespaces extend the baseline when supported by the nodes.
See the [compatibility and hardening matrix](docs/secure-deployment.md#kubernetes-compatibility-and-hardening).
The first **0.1.0**
release is being prepared; published artifacts and evidence will appear in the
[release history](https://github.com/Alien6-Studio/hankoshell-operator/releases).
The `0.x` series is in initial development, and public APIs may change between
minor versions before `1.0.0`.

Start with the [chart configuration](charts/hankoshell-operator/README.md) and
the [secure deployment steps](docs/secure-deployment.md#configure-an-installation).
Prepare `operator-values.yaml` for the actual cluster: a verified image digest,
Keycloak endpoint and existing credentials Secret, authority realm, and exact
Kubernetes API, DNS and provider destinations.

Install the reviewed source chart after configuring those values:

```sh
kubectl apply -f charts/hankoshell-operator/crds/
helm upgrade --install hankoshell-operator ./charts/hankoshell-operator \
  --namespace auth --create-namespace \
  --values operator-values.yaml --wait --timeout 5m
```

The operator watches its release namespace. Kubernetes API egress is closed
until explicitly configured. Helm does not upgrade CRDs: review and apply the
schemas separately before each upgrade. The chart uses standard Kubernetes
APIs; validate networking and storage on the target cluster. Source checks do
not certify EKS, GKE, AKS, Scaleway or other hosted installations.

### Declare your first realm

These resources declare an `example` realm and a public SPA client for a customer
portal. The operator creates or reconciles their Keycloak configuration, including
the portal's allowed login callback and logout destination. The realm uses
provider authentication defaults; attach
a reviewed `HankoIAMProfile` when defining your deployment's authentication
policy.

```yaml
apiVersion: hanko.sh/v1alpha1
kind: HankoRealm
metadata:
  name: example
  namespace: auth
spec:
  displayName: Example
  roles:
    - name: viewer
      description: Read-only application access
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
  realmRoleScopes:
    - viewer
```

```sh
kubectl apply -f portal-identity.yaml
kubectl get hankorealm example --namespace auth
kubectl get hankoapplication customer-portal --namespace auth
```

Replace the example URLs with your application's actual endpoints. The SPA still
needs its OIDC configuration and login flow; this declares the Keycloak side.
`realmRoleScopes` limits which realm roles may appear in its tokens and does not
assign the `viewer` role to users.

Review resource ownership and finalizers before deleting managed resources:
deletion can remove their corresponding Keycloak objects.

## Choose provider ownership

The official Keycloak operator is optional. `HankoKeycloakInstance` selects
which responsibilities hankoShell owns:

| Mode | Behavior |
| --- | --- |
| `external` | Reconcile IAM through an existing provider's Admin API; its workloads remain with their current owner. |
| `managed` | Provision a Keycloak Deployment using the declared image and database Secret. |
| `adopted` | Reference an existing Kubernetes Deployment for supported operational integrations. |

Use one management writer per provider object. Theme rollout integrations are
Deployment-based; provider workload ownership and IAM ownership are separate.

## Platform integrations

The Keycloak workflow above can run on its own. The hankoShell API and Hub are
optional extensions for organization projection, cluster supervision and fleet
synchronization.

`profile: standard` works independently of Continuum. Enable API organization
projection, supervision or Hub synchronization when those services are
installed and their credentials and destinations have been configured.

`profile: enterprise` requires an existing Continuum node installation, a
private Hub relay, verified TLS 1.3, an immutable operator image and baseline
NetworkPolicy. See the [enterprise requirements](docs/secure-deployment.md#enterprise-profile).
Optional Cilium policies require the corresponding cluster capabilities;
the operator runs without BPF privileges. Workload mesh policy projection is
currently an audit path, not an enforcement claim.

Hub bundles use a token-derived HMAC. Every holder of that token can produce
the same authenticator; there is no independent bundle publisher signature.
The [trust model](docs/secure-deployment.md#hub-bundle-authentication) explains
the distinction from Ed25519 mesh policies and signed release evidence.

Platform messaging and vault credentials belong to the hankoShell API.
`HankoEmailProvider` is retained for upgrades; its controller clears old
readiness without reading credentials or sending email. Keycloak owns its
authentication emails and realm SMTP settings. Auth0 integration is not
implemented. Existing installations should follow the
[upgrade and rollback procedure](docs/secure-deployment.md#upgrade-and-rollback).

## Verified delivery

The release workflow builds Linux AMD64/ARM64 images and the Helm chart from a
reviewed SemVer tag. Passing CI, image signing, BuildKit provenance and a signed,
timestamped **Continuum Attest** delivery receipt are required before chart and
repository-metadata publication. The receipt binds artifact hashes, the image
digest and source revision; it does not supervise the image build itself.

Verify release receipts against an independently trusted signer and TSA.
Installation-time image admission remains an administrator-owned control; see
[secure deployment](docs/secure-deployment.md).

<details>
<summary>Release configuration for maintainers</summary>

Configure the release environment secret `HANKOSHELL_ATTEST_SIGNING_KEY`
(PKCS#8 PEM) and variables `HANKOSHELL_ATTEST_KEY_ID`,
`HANKOSHELL_ATTEST_PUBLIC_KEY` (32 bytes as lowercase hex),
`HANKOSHELL_ATTEST_TSA_URL`, and `HANKOSHELL_ATTEST_TSA_CERTIFICATE` (pinned PEM).

Register `oci://ghcr.io/alien6-studio/charts/hankoshell-operator` in Artifact Hub
and set `HANKOSHELL_ARTIFACTHUB_REPOSITORY_ID` to its assigned UUID. The workflow
includes `artifacthub-repo.yml` in the verified delivery and publishes it under
the OCI tag `artifacthub.io`. Verified Publisher is granted by Artifact Hub
after matching that ID during indexing. Security reports use GitHub private
vulnerability reporting. Configure public artifact access before launching the release.

`artifacthub.io/signKey` links the Ed25519 public key for the Attest receipt.
The release also provides a keyless Sigstore bundle; these are separate from
Helm's OpenPGP `.prov` verification.

</details>

## Development

Use Go 1.27.1, Helm 3.17 or later, Python 3, and a C compiler for race tests.

```sh
python3 -m pip install -r scripts/requirements.txt
make install-tools
make check arch lint generated-check vuln
python3 -m unittest discover -s scripts -p 'test_*.py'
make build
make integration-test KUBERNETES_VERSION=1.37.0
```

`make lint` installs and verifies golangci-lint **v2.14.0** under `.tools`.
CRDs are generated with the pinned controller-gen version. Unit tests use simulated
Kubernetes clients and HTTP/TLS servers. `make integration-test` downloads official
API-server/etcd fixtures with pinned SHA-512 checksums and starts a local control
plane. CI runs it on **1.35.0, 1.36.2 and 1.37.0**; all matrix jobs must pass before
merge or delivery. These API tests do not run kubelets, CNI, CSI or Keycloak;
target-cluster qualification remains part of an installation's acceptance checks.

[Contributing](CONTRIBUTING.md) · [Code of conduct](CODE_OF_CONDUCT.md) ·
[Report a vulnerability](SECURITY.md) ·
[Report an issue](https://github.com/Alien6-Studio/hankoshell-operator/issues) ·
[Apache-2.0](LICENSE)

The product name is **hankoShell**; repository, module, chart, image and binary
use `hankoshell-operator`. Existing `hanko.sh`, `Hanko*`, `HANKO_*` and Kubernetes
names/selectors are preserved for compatibility.
