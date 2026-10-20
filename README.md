# hankoShell Operator

Application IAM contracts for Kubernetes, reconciled to Keycloak.

hankoShell Operator turns application identity, authentication and authorization
requirements into continuously reconciled Keycloak configuration: login clients,
redirect URLs, roles, token claims and machine credentials. Declare the desired
configuration in Kubernetes, review it in Git, and let the operator keep the
fields it manages in sync with Keycloak.
Keycloak is the supported IAM backend. An opt-in
[authentik 2026.8.4 registration experiment](docs/architecture/second-provider.md)
executes a bounded OIDC SPA/web subset. Roles, organizations, authorization graphs,
M2M, SAML, federation, delegation and credential delivery remain unsupported on
that adapter. The shared fourteen-fixture corpus checks this registration window
through the installed chart on Kubernetes 1.35.0/1.36.2/1.37.0 with both supported
Keycloak versions. Keycloak-native features remain available.

Platform teams can reuse authentication policies across realms, connect upstream
identity providers and rotate client secrets. Application teams can keep their
login and access configuration with their deployment manifests. It works with
an existing Keycloak instance within the [qualified version window](docs/secure-deployment.md#keycloak-compatibility),
including one managed by the official Keycloak operator, and can also provision
a Keycloak Deployment. Reconciliation updates only the supported fields and
resources under the operator's ownership.

ResourceServer status explains the observed structural origins of grants, including
organizations and role composites, without enumerating users. See the
[provenance contract](docs/architecture/organizational-authorization.md#bounded-effective-explanation).

The standalone Keycloak use case needs neither hankoShell Hub nor Continuum.
Those optional integrations connect the operator to the wider platform and
enterprise fleet. Project website: **[hanko.sh](https://hanko.sh)**.

**[What it manages](#what-it-manages-in-keycloak)** · [First application](#declare-your-first-realm) ·
[Deployment](#deployment) ·
[Secure deployment and trust model](docs/secure-deployment.md) ·
[Keycloak permissions](docs/keycloak-permissions.md) ·
[OIDC/SAML application model and migration](docs/architecture/application-identity.md) ·
[Changes](CHANGELOG.md) · **[Release 1.0.0](https://github.com/Alien6-Studio/hankoshell-operator/milestone/11)** · [IAM contract architecture](docs/architecture/iam-contract-engine.md) ·
[Organizational grants and provenance](docs/architecture/organizational-authorization.md)

[![CI](https://github.com/Alien6-Studio/hankoshell-operator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Alien6-Studio/hankoshell-operator/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.0--dev.0%20development-blue.svg)](#release-maturity)
[![Go](https://img.shields.io/badge/go-1.27.2-00ADD8.svg)](go.mod)
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
| Application clients | OIDC SPA, web and machine clients; callbacks, roles, claims and credentials. Qualified SAML POST/signing/ACS and UID-bound runtime metadata/credential delivery. |
| Authentication policies | Reusable MFA, password, session, brute-force, email-verification and authentication-event settings. |
| Identity brokering | Upstream identity providers and their Keycloak mappers, with provider credentials referenced from Secrets. Application mappings can turn upstream OIDC claims into roles or user attributes. |
| Token contents | Client-specific claims from user attributes or fixed values, with control over the declared realm roles included in application tokens. |
| Roles and API permissions | Realm and client roles, composite realm roles, and resource-server scopes, resources and permissions for role or workload principals. |
| Organization grants | Direct or explicit declared-descendant grants through owned structural groups; [permissions, bounds and consistency](docs/keycloak-permissions.md#organization-principals-010). |
| Machine credentials | Service-account clients, confidential client secrets, scheduled or requested rotation, and explicitly authorized application Secret projections. |
| Existing configuration | Import reports and supported realm, client, service-account and identity-provider configuration; observe existing objects before taking ownership. |

`HankoApplication.spec.protocol` defaults to `oidc`, retaining existing OIDC
field paths. The SAML subset supports:
exact HTTPS ACS destinations, signed responses/assertions, four NameID formats,
client roles and public IdP metadata in status. See the
[application contract](docs/architecture/application-identity.md) for fields,
qualification and unsupported features. Clients installed from legacy source installations without a UID marker
require reviewed UUID + observation approval; protocol conversion requires
reviewed deletion/recreation.

**[Runtime bindings](docs/architecture/application-identity.md#runtime-bindings)**
deliver a versioned `identity.json` ConfigMap and optional confidential OIDC Secret
to preauthorized workload targets. Delivery binds the current ServiceAccount UID,
requires proven applied provider state and preserves unrelated target data. No SDK
or automatic pod restart is needed. Source metadata is 0.1.0-dev.0; public packages and
a GitHub Release remain pending.

`HankoRole` management and deletion require the CR UID ownership marker in
Keycloak. Existing unmarked roles require administrator-reviewed adoption; see
[role ownership and migration](docs/architecture/iam-contract-engine.md#local-authority-freshness-and-ownership).

Use one writer for each managed Keycloak object. Observation mode does not
modify provider objects or read their client secrets; management mode owns their
supported lifecycle. General user provisioning and LDAP synchronization are not
exposed as dedicated resources. Keycloak remains responsible for user login,
token issuance and its authentication emails.

<details>
<summary>Custom resource reference</summary>

| Area | Custom resources |
| --- | --- |
| Identity and access | `HankoRealm`, `HankoApplication`, `HankoRole`, `HankoIAMProfile`, `HankoServiceAccount`, `HankoResourceServer`, `HankoWorkloadTrust` |
| Provider instances and imports | `HankoKeycloakInstance`, `HankoImport` |
| Platform and fleet integration | `HankoOrganization`, `HankoIssuer`, `HankoTenant`, `HankoMeshService` |
| Workload operations | `HankoTheme`, `HankoSnapshot`, `HankoOperation` |

The API provides 17 `hanko.sh/v1alpha1` custom resources, including the deprecated
`HankoEmailProvider`. See the [API definitions](api/v1alpha1) for supported fields.
Integration flags configure clients and do not disable controller registration.

<!-- api-support:start -->
All 17 `hanko.sh/v1alpha1` resources are experimental; no public API compatibility commitment has been selected. Candidate `v1beta1` additionally serves Application, Role and ResourceServer with identical schemas; storage remains `v1alpha1`.

| Resource | Surface | Compatibility |
| --- | --- | --- |
| `HankoApplication` | standalone IAM | experimental |
| `HankoEmailProvider` | deprecated | experimental |
| `HankoIAMProfile` | standalone IAM | experimental |
| `HankoImport` | instance and operations | experimental |
| `HankoIssuer` | standalone IAM | experimental |
| `HankoKeycloakInstance` | instance and operations | experimental |
| `HankoMeshService` | connected | experimental |
| `HankoOperation` | instance and operations | experimental |
| `HankoOrganization` | standalone IAM | experimental |
| `HankoRealm` | standalone IAM | experimental |
| `HankoResourceServer` | standalone IAM | experimental |
| `HankoRole` | standalone IAM | experimental |
| `HankoServiceAccount` | standalone IAM | experimental |
| `HankoSnapshot` | instance and operations | experimental |
| `HankoTenant` | connected | experimental |
| `HankoTheme` | instance and operations | experimental |
| `HankoWorkloadTrust` | standalone IAM | experimental |

| Additional surface | Compatibility |
| --- | --- |
| Delegation and agent identity | experimental |
| Second IAM provider | experimental |
| Hub and Continuum | alpha |
| Mesh traffic enforcement | experimental |
| Portable backup and restore | experimental |
| Managed lifecycle | experimental |
| Cloud, CNI and CSI | experimental |
<!-- api-support:end -->

See the [support and field-group inventory](docs/api-support.md) and
[API migration policy](docs/api-migration-policy.md).
Use the [storage migration runbook](docs/storage-migration.md) before changing
storage or applying CRDs to an existing installation with the beta candidate.
Snapshot database Jobs require a locally approved, publisher-verified image digest
and a dedicated backup credential Secret. PostgreSQL/PVC configuration and
portable backup/restore remain installation-specific and unqualified; see the
[backup execution contract](docs/secure-deployment.md#database-snapshot-jobs).
`HankoOperation`'s `Upgrade`, `Clone` and `DBSwitch` workflows are experimental in
0.1.0. Installed qualification covers the same-namespace, configuration-only Clone
alias subset on Kubernetes 1.37.0 / Keycloak 26.8.0, including checkpoint restart
and child failure/refusal. Managed upgrades, database-reference switches and
database recovery remain unqualified. See the
[lifecycle qualification limits](docs/secure-deployment.md#lifecycle-operation-qualification).

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

For an existing realm, the tested common service-account profile uses only
`manage-realm`, `manage-clients` and `manage-events` on that target realm.
See the **[Keycloak permission model](docs/keycloak-permissions.md)** before
provisioning credentials: it specifies optional feature roles, read-only import,
forbidden authority and the broader native grants attached to realm creation.

The exact current Keycloak qualification versions are listed in the generated support window below
through its real HTTPS Admin API v1. Required CI exercises realm/client lifecycles,
IAM/MFA settings, roles, identity-provider configuration, secret rotation,
drift recovery, ownership, finalizers and read-only import. Other 26.x patches
may work but are unqualified; older and future major lines are outside the
current qualification contract pending qualification. CI also qualifies OIDC browser/PKCE, M2M and
signed SAML POST application flows on these same versions; see the
[protocol evidence and limits](docs/architecture/application-identity.md#protocol-and-xml-security-qualification).
External identity-provider handshakes and production database/cluster operations
remain unqualified.
See the [Keycloak compatibility contract](docs/secure-deployment.md#keycloak-compatibility).

The chart targets the Kubernetes minors in the generated support window below, on Linux nodes. Required CI checks
qualify all 17 CRDs, server-side apply, namespace/credential RBAC boundaries and
Restricted Pod Security admission against each minor version. Optional AppArmor
and stable user namespaces extend the baseline when supported by the nodes.
An installed-system test retains its 19 general checks on Kubernetes 1.37.0
with HTTPS Keycloak 26.8.0. A separate installed workload matrix qualifies the
exact scanned image across every declared Kubernetes/Keycloak pair:
real projected 600-second Pod assertions, client credentials grants, independent
native resource ALLOW/DENY, kubelet rotation/expiry and UID containment.
Deep reviewed migration/recovery runs on both Keycloak versions with 1.37.0.
See the [compatibility and hardening matrix](docs/secure-deployment.md#kubernetes-compatibility-and-hardening).
Published artifacts and evidence are listed in the
[release history](https://github.com/Alien6-Studio/hankoshell-operator/releases).

Start with the [chart configuration](charts/hankoshell-operator/README.md) and
the [secure deployment steps](docs/secure-deployment.md#configure-an-installation).
Prepare `operator-values.yaml` for the actual cluster: a verified image digest,
Keycloak endpoint and existing credentials Secret, authority realm, and exact
Kubernetes API, DNS and provider destinations. Approve exact credential output
and managed Deployment names through [`sensitiveWrites`](docs/secure-deployment.md#exact-secret-and-deployment-write-authority),
and configure current Restricted Pod Security admission on the operator namespace.

**Keycloak administrative connections require verified HTTPS by default.** Public
CA certificates need no CA Secret; private CAs use `keycloak.caSecret` or an
instance's `spec.tlsCARef`. The administrative credential, bearer tokens and
Admin API traffic are security-sensitive. Existing HTTP installations must
explicitly set `keycloak.allowInsecureHTTP: true` and review their egress ports;
HTTP provides no transport confidentiality or server authentication. Enterprise
remains HTTPS-only. See the [transport contract and migration](docs/secure-deployment.md#keycloak-administrative-transport).

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

Metrics are disabled by default. Enabling the endpoint requires TLS 1.3, a trusted
client certificate and an exact client URI SAN allowlist. ServiceMonitor uses
mutual TLS; annotation discovery is removed. Operational procedures: [runbooks](docs/operations-runbooks.md), [secure observability](docs/operational-observability.md) and the [machine contract](docs/operational-contract.json).


## Choose provider ownership

The official Keycloak operator is optional. `HankoKeycloakInstance` selects
which responsibilities hankoShell owns:

| Mode | Behavior |
| --- | --- |
| `external` | Reconcile IAM through an existing provider's Admin API; its workloads remain with their current owner. |
| `managed` | Provision a Keycloak Deployment using the declared optimized image, database Secret and serving TLS Secret; expose HTTPS/8443. |
| `adopted` | Reference an existing Kubernetes Deployment for supported operational integrations. |

Use one management writer per provider object. Theme rollout integrations are
Deployment-based; provider workload ownership and IAM ownership are separate.

Managed HTTPS requires `spec.managed.tlsSecretRef`, containing the server
certificate/key. `spec.tlsCARef` separately configures client trust for a private
CA. The image must be built for its database with health checks enabled.
See [managed transport and migration](docs/secure-deployment.md#managed-keycloak-transport).

Instance reconciliation probes Keycloak without changing `master` or rotating
`AdminRef` credentials by default. Enable `spec.hardenMasterRealm` or
`spec.rotateAdminCredentials` only when assigning those responsibilities to the
operator. An adopted Service is labelled for platform discovery only with
`spec.adopted.publishDiscovery: true`. See the [permission model](docs/keycloak-permissions.md).

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

Hub synchronization defaults to a token-derived HMAC. Signed fleet mode uses
independently approved Ed25519 publisher keys, exact target/source bindings and
a persisted sequence checkpoint. Enable it explicitly with
`fleetPlanVerification.trustConfigMap` after provisioning local trust and a
compatible Hub. See the [Fleet contract](docs/architecture/fleet-reconciliation.md)
and [activation guide](docs/secure-deployment.md#signed-fleet-plan-transition).
Capability-aware all-or-refuse/partial delivery and independent local pause are
available experimentally. Disconnected provider authorization, rollback and
installed fleet qualification remain #79/#80.

Hub self-updates require an independently approved release and verified image
signature. Remote decommission commands expire at their deadline. See
[remote command authorization](docs/secure-deployment.md#hub-remote-commands).

Platform messaging and vault credentials belong to the hankoShell API.
`HankoEmailProvider` is retained for upgrades; its controller clears old
readiness without reading credentials or sending email. Keycloak owns its
authentication emails and realm SMTP settings. Auth0 integration is not
implemented. Existing installations should follow the
[upgrade and rollback procedure](docs/secure-deployment.md#upgrade-and-rollback).

## Verified delivery

Production publication is blocked while the source is `0.1.0-dev.0`.
The future first release requires an explicitly prepared stable candidate,
a GitHub-verified source commit and a GitHub-verified signed annotated
`v0.1.0` tag bound to that exact commit on protected main. The expected source
ref is `refs/tags/v0.1.0` and GitHub display name is `v0.1.0`.
The workflow rejects unverified signatures, lightweight tags and conflicting or
moved references, and checks these identities again before publication.
It builds Linux AMD64/ARM64 images and the Helm chart from that source.
CI scans the final OCI image, including embedded `cosign`,
on both architectures with checksum-pinned Trivy. The [OCI vulnerability policy](SECURITY.md#final-oci-image-vulnerability-gate)
blocks fixable HIGH/CRITICAL findings, with only scoped temporary HIGH exceptions.
The same scanned archive/digest is copied, signed and selected by the packaged
chart; it is never rebuilt after scanning. Passing CI, image signing, BuildKit
provenance and a signed, timestamped **Continuum Attest** delivery receipt are
required before assigning the release image tag and publishing the chart and
repository metadata. Full JSON scan reports and the policy enter release
checksums and the receipt. The receipt binds artifact hashes, the image
digest and source revision; it does not supervise the image build itself.

Verify release receipts against an independently trusted signer and TSA.
Installation-time image admission remains an administrator-owned control; see
[secure deployment](docs/secure-deployment.md).

<details>
<summary>Release configuration for maintainers</summary>

Configure the release environment secret `HANKOSHELL_ATTEST_SIGNING_KEY`
(Ed25519 PKCS#8 PEM) and variables `HANKOSHELL_ATTEST_KEY_ID`,
`HANKOSHELL_ATTEST_PUBLIC_KEY` (32 bytes as lowercase hex),
`HANKOSHELL_ATTEST_TSA_URL`, and `HANKOSHELL_ATTEST_TSA_CERTIFICATE` (pinned PEM).
Derive the Key ID with the pinned Attest 0.1.0 `keys import`/`keys list` commands
using only the approved public key. It is the first 16 bytes of BLAKE3 of the raw
32-byte public key, encoded as 32 lowercase hex characters, not a chosen label
or a SHA-256 prefix. The release preflight checks the private/public pair, native
Key ID and X.509 certificate parsing before staging any image.

Register `oci://ghcr.io/alien6-studio/charts/hankoshell-operator` in Artifact Hub
and set `HANKOSHELL_ARTIFACTHUB_REPOSITORY_ID` to its assigned UUID. The workflow
includes `artifacthub-repo.yml` in the verified delivery and publishes it under
the OCI tag `artifacthub.io`. Verified Publisher is granted by Artifact Hub
after matching that ID during indexing. Security reports use GitHub private
vulnerability reporting. Configure public artifact access before launching the release.

The chart's named Attest verification-key link identifies the Ed25519 key for
the delivery receipt. The release also provides a keyless Sigstore bundle.
Neither is a Helm OpenPGP `.prov` signature; the chart does not advertise a
Helm signing key through `artifacthub.io/signKey`.

</details>

## Release maturity

**hankoShell Operator 0.1.0 is in initial development. No public release has been
published yet.** Active chart/app/build metadata is `0.1.0-dev.0` (prerelease).
The implemented foundation, IAM contracts, application identity, organizational
authorization, adoption and canonical Attest hardening remain intact. Workload
Identity, Delegation & Agent Identity, Provider Portability, Fleet Reconciliation
and Initial Public Contract Stabilization are required before first publication.
Track the remaining work in the [Release 1.0.0 milestone](https://github.com/Alien6-Studio/hankoshell-operator/milestone/11) and
[first-publication checklist](docs/release-public-0.1.0-preparation.md).
The `hanko.sh/v1alpha1` APIs are experimental and may change across minor releases
before 1.0. See the [curated release
overview](CHANGELOG.md#release-overview) for capabilities and qualification limits.

The [release rehearsal](docs/secure-deployment.md#release-rehearsal-and-publication)
is required CI and writes only to an isolated test registry. Production delivery additionally
requires configured release trust, public registry access and an assigned
Artifact Hub repository ID. OCI promotion and GitHub draft creation are separate
operations; verified packages can exist before the GitHub Release is published.
Retries restore the committed delivery, rescan its exact image and reuse matching
packages and draft assets. Conflicting content stops publication.

HankoOrganization can be Ready without the hankoShell API. `Synced` reports
Keycloak convergence; `Projection` separately reports the optional configured
API integration. A projection outage preserves provider success and does not
block child Keycloak groups. See [organization configuration and migration](docs/secure-deployment.md#organization-provider-readiness-and-optional-projection).

Existing Keycloak inventory produces bounded adoption candidates and typed diffs.
Adopt Existing Keycloak source work adds reviewed leaf and aggregate ownership, followed by a
separate explicit Manage decision. See the
[adoption workflow](docs/architecture/existing-keycloak-adoption.md#administrator-workflow)
and [native preservation boundaries](docs/architecture/existing-keycloak-adoption.md#milestone-native-coverage-audit).
**Existing unmarked M2M clients require reviewed acquisition before provider
writes, credential recovery/rotation or deletion.** Acquisition preserves UUIDs,
writes only ownership checkpoints and remains Observe. Manage requires current
exact ownership and qualified preservation; foreign dependencies hold cleanup.
Existing realms and opaque brokers remain Observe-only. Adopt Existing Keycloak
completes reviewed adoption and qualified native preservation; public distribution
remains independent in #21.

HankoRole Manage uses target-realm `manage-realm`, which also permits target-realm
security changes and deletion: credential compromise exposes the complete target
realm. HankoRole never performs those realm operations;
ownership markers do not narrow the credential's technical capabilities. Use a
dedicated scoped writer where possible and review the
[role-writer permission boundary](docs/keycloak-permissions.md#dedicated-hankorole-writer-target-realm-exception).

## Development

The experimental bounded-delegation Java extension is maintained in
[Alien6-Studio/keycloak-bounded-delegation](https://github.com/Alien6-Studio/keycloak-bounded-delegation),
a sibling checkout of this repository and `hanko-platform`. The operator keeps
its adapter and [immutable consumer pin](extensions/keycloak-bounded-delegation.json).
`make keycloak-extension-test KEYCLOAK_VERSION=VERSION` builds that exact source
and checks the JAR's source, SDK and SHA256 before real HTTPS interoperability.
Installed and multi-node delegation qualification remains in
[#71](https://github.com/Alien6-Studio/hankoshell-operator/issues/71).

Adopt Existing Keycloak completes reviewed acquisition, native
preservation and explicit Manage. Organizational Authorization retains explicit
grants and bounded structural provenance. **Workload Identity is implemented and
qualified as an installed system** within the [supported contract](docs/architecture/workload-identity.md#installed-system-and-migration-qualification).
Kubernetes workload trust ownership and Workload binding and mesh coherence have
typed APIs and controllers. HankoServiceAccount federated authentication adds
owned native activation, durable reviewed mode changes and explicit Secret
fallback. Public metadata follows verified configuration; the operator never
receives workload JWTs. [The migration contract](docs/architecture/workload-identity.md#hankoserviceaccount-federated-authentication)
retains two-client migration as the default. Same-client cutover, same-credential
Secret fallback, return and journal recovery are qualified on both Keycloak
versions with Kubernetes 1.37.0. Same-client cutover has no zero-downtime guarantee;
containment is asynchronous and does not revoke already issued access tokens.
[#21](https://github.com/Alien6-Studio/hankoshell-operator/issues/21) remains
open for transversal first-publication trust and readiness.
For `HankoRole` and `HankoResourceServer`, status distinguishes the evaluated
intent/plan, the latest Manage application proven by provider read-back, and the
latest provider observation with explicit drift/coverage. Observe never claims
application. See [status semantics and migration](docs/architecture/iam-contract-engine.md#public-status-evidence).

Use Go 1.27.2, Helm 3.17 or later, Python 3, and a C compiler for race tests.

```sh
python3 -m pip install -r scripts/requirements.txt
make install-tools
make check arch lint generated-check vuln
python3 -m unittest discover -s scripts -p 'test_*.py'
make build
make integration-test KUBERNETES_VERSION=1.37.0
make keycloak-integration-test KEYCLOAK_VERSION=26.8.0
make keycloak-integration-test KEYCLOAK_VERSION=26.7.5
```

`make lint` installs and verifies golangci-lint **v2.14.0** under `.tools`.
CRDs are generated with the pinned controller-gen version. Unit tests use simulated
Kubernetes clients and HTTP/TLS servers. `make integration-test` downloads official
API-server/etcd fixtures with pinned SHA-512 checksums and starts a local control
plane. CI runs it on every Kubernetes version declared in `versions.json`; all matrix jobs must pass before
merge or delivery. These API tests do not run kubelets, CNI, CSI or Keycloak;
target-cluster qualification remains part of an installation's acceptance checks.

`make keycloak-integration-test` requires a running Docker daemon and pulls the
official image pinned by digest. It starts a disposable HTTPS-only server with
ephemeral credentials and certificate trust, reconciles through the real Admin
API, and removes only its own container. Startup failures fail the test. Both
Keycloak versions are required in PR, weekly and release quality checks; the
suite uses a fake Kubernetes client alongside the separate real Kubernetes matrix.

`make system-test` installs the chart and scanned OCI image in a disposable kind
1.37.0 cluster with HTTPS Keycloak 26.8.0. It exercises real controllers, Secrets,
scoped RBAC, realm/application/role reconciliation, observation, restart/drift
recovery and finalizer deletion. It requires Docker, checksum-pinned kind/kubectl,
Helm 3.17.0, pinned ORAS and the fresh OCI archive/evidence from CI; see the
[reproduction command](docs/secure-deployment.md#installed-system-test).
`make workload-installed-test` consumes the same fresh scanned archive, revision
and digest. CI requires six runtime cells and two deep migration/recovery cases;
see [stratification and reproduction](docs/secure-deployment.md#installed-workload-identity-qualification).
The single-node/dev-file fixtures do not qualify CNI policy enforcement, cloud
providers, production databases, enterprise fleet integration or disaster recovery.

[Contributing](CONTRIBUTING.md) · [Code of conduct](CODE_OF_CONDUCT.md) ·
[Report a vulnerability](SECURITY.md) ·
[Report an issue](https://github.com/Alien6-Studio/hankoshell-operator/issues) ·
[Apache-2.0](LICENSE)

## Initial public contract selection

See the [complete candidate review](docs/public-contract-selection.md).

<!-- public-selection:start -->

Initial 0.1.0 selection: 3 public resource candidates; qualification and first publication remain pending. Current development APIs remain experimental.

| Resource | Selected scope | Public spec groups |
| --- | --- | --- |
| `HankoApplication` | public | `clientID`, `mode`, `postLogoutRedirectURIs`, `protocol`, `realmRef`, `realmRoleScopes`, `redirectURIs`, `roles`, `saml`, `type`, `webOrigins` |
| `HankoEmailProvider` | experimental | — |
| `HankoIAMProfile` | alpha | — |
| `HankoImport` | experimental | — |
| `HankoIssuer` | alpha | — |
| `HankoKeycloakInstance` | experimental | — |
| `HankoMeshService` | experimental | — |
| `HankoOperation` | experimental | — |
| `HankoOrganization` | alpha | — |
| `HankoRealm` | alpha | — |
| `HankoResourceServer` | public | `applicationRef`, `audience`, `displayName`, `mode`, `permissions`, `realmRef`, `resources`, `scopes` |
| `HankoRole` | public | `composite`, `composites`, `description`, `mode`, `name`, `realmRef` |
| `HankoServiceAccount` | alpha | — |
| `HankoSnapshot` | experimental | — |
| `HankoTenant` | experimental | — |
| `HankoTheme` | experimental | — |
| `HankoWorkloadTrust` | alpha | — |

Native SAML and CORS entry policy remain Keycloak extensions. Delegation, organization principals,
connected integrations and every other deferred field retain their named limitations in
the complete selection; no planned capability is removed.

<!-- public-selection:end -->

The [1.0 graduation criteria and per-resource records](docs/stable-graduation.md)
and [second-provider contract review](docs/stable-provider-review.md) remain
unratified development inputs. Lifecycle APIs are excluded from the stable 1.0
contract and disabled by default; see [ADR-050](docs/architecture/decisions/ADR-050-experimental-lifecycle-authority.md).

Qualification window: [support policy](docs/support-window.md), [compatibility proposal](docs/compatibility-policy.md), [production evidence reporting](docs/production-evidence.md).

Load and recovery qualification: [bounded IAM workers, installed scale and soak](docs/scale-and-soak.md).

<!-- support-window:start -->
| Component | Exact qualification versions | Default |
| --- | --- | --- |
| kubernetes | `1.35.0`, `1.36.2`, `1.37.0` | `1.37.0` |
| keycloak | `26.7.5`, `26.8.0` | `26.8.0` |
<!-- support-window:end -->
