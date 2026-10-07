# Secure deployment and trust model

Use this guide with the [chart configuration](../charts/hankoshell-operator/README.md),
[values](../charts/hankoshell-operator/values.yaml) and [security policy](../SECURITY.md).
An installation needs reviewed credentials, provider ownership and network
destinations before the operator can reconcile resources.

## Trust boundaries

The Kubernetes API server, cluster administrators and the configured Keycloak
provider are trusted. Anyone who can change watched CRDs or the operator's
credentials can influence provider operations within its granted authority.
Limit that access with Kubernetes RBAC and provider permissions; the namespace
watch boundary is not a separate trust boundary between mutually hostile tenants.

The operator reads credentials from Secrets and uses service-account access
to reconcile provider state. Protect Secrets at rest with the cluster's
encryption/KMS configuration and limit read access. A compromised operator pod
can exercise its granted Kubernetes and provider permissions; workload hardening
does not eliminate those privileges. A compromised cluster administrator, Hub
or provider is outside the protection offered by these client-side controls.

### Hub bundle authentication

The bundle endpoint returns an HMAC-SHA256 over `JSON(Bundle)` using
`SHA256(bearer_token)` as its key. Verification checks integrity against that
shared credential. Every holder of the bearer token can derive the same key
and forge an accepted bundle. This is not independent publisher authentication,
non-repudiation, or protection after bearer-token compromise. Hashing a weak
token does not add entropy. The bundle authenticator also does not establish
a separately signed expiration or anti-replay sequence.

Authenticate the Hub endpoint with verified HTTPS, scope and rotate operator
credentials, and revoke them after suspected disclosure. In the enterprise
profile, synchronization is bound to the configured private relay and Hub TLS
name. Those controls protect transport and destination; they do not convert
the shared HMAC into an independent signature.

Independent bundle publisher verification would require a coordinated Hub
protocol with a separately trusted signing key and explicit tenant, freshness
and key-rotation bindings. The current bundle wire contract remains HMAC.

Ed25519 mesh-policy envelopes are a different protocol. The operator carries
the exact bounded response bytes and requires the `audit-only` mode binding;
Continuum is responsible for signature and trust-context verification. This
does not authenticate IAM bundles or establish workload enforcement by itself.

### Bounded HTTP responses

Hub requests have a 10-second client timeout. Response budgets apply to bytes
read from the HTTP body, including bodies decompressed by the standard transport:

| Response | Maximum size |
| --- | --- |
| IAM bundle or mesh-policy envelope | 1 MiB |
| Enrollment, rotation or heartbeat acknowledgement | 64 KiB |
| Error diagnostics | 8 KiB |

Oversize and failed reads return errors, even if the prefix is valid JSON.
Bodies are closed and partial heartbeat commands are discarded. Larger bundles
must be reduced before rollout; the client does not silently truncate them.

## Configure an installation

### Kubernetes compatibility and hardening

The operator and chart keep their own SemVer (`0.1.0`); they do not share the
cluster's version number. Kubernetes libraries are upgraded together:
`k8s.io/{api,apimachinery,client-go,apiextensions-apiserver}` **v0.37.1** and
`controller-runtime` **v0.25.2**, following its
[compatibility table](https://github.com/kubernetes-sigs/controller-runtime#compatibility).

The chart accepts Kubernetes **1.35–1.37**, including managed-provider version
suffixes, and rejects upstream alpha/beta/RC builds and unqualified future minors.
The qualification window follows the three recent upstream minors; consult the
[Kubernetes release/support dates](https://kubernetes.io/releases/) and install
the latest security-patched version offered by your provider within that window.
Provider extended support for an older cluster does not qualify this chart for it.

| Kubernetes minor | Pinned CI API-server fixture | Baseline | Optional AppArmor | Optional user namespaces |
| --- | --- | --- | --- | --- |
| 1.35 | 1.35.0 | Restricted admission, non-root, seccomp, dropped capabilities, read-only filesystem, NetworkPolicy | Node support required | Rejected: feature not yet stable |
| 1.36 | 1.36.2 | Same mandatory baseline | Node support required | Node/runtime support required |
| 1.37 | 1.37.0 | Same mandatory baseline | Node support required | Node/runtime support required |

CI starts a real API server and etcd for each fixture, installs all 16 CRDs and
validates chart resources with strict server field validation. It tests actual
Restricted pod admission, including rejection of host networking, host probes,
privileged containers and BPF capabilities; server-side apply preserves explicit
`false`/`0`, CEL validation and status updates work, and RBAC denies cross-namespace
access and Secret enumeration. The required check aggregates every matrix result,
and the release workflow reuses that gate before Attest delivery.
The same CI, including vulnerability checks, runs weekly on `main`. Review the
upstream support window before each release; changing the SDK family or cluster
window requires updating and passing the compatibility tests together.

The API fixtures are reproducible compatibility tests, not recommended production
patches. They have no kubelet, CNI, CSI, provider or Keycloak process. AWS, Google,
Azure, Scaleway and other installations still need acceptance tests of networking,
storage, provider lifecycle and restore on their actual patched clusters.

The operator workload is scheduled on Linux nodes. Set `hardening.appArmor: true`
only after verifying that AppArmor is enabled on every eligible node; it requests
`RuntimeDefault` and cannot run on nodes lacking that support. Set
`hardening.userNamespaces: true` on Kubernetes **>=1.36** only after qualifying
Linux **>=6.3**, idmap-capable filesystems (including mounted volumes) and compatible
CRI/OCI runtimes. Kubernetes documents these
[user namespace requirements](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/).
This sets `hostUsers: false`. The chart rejects the option on 1.35, even if the
cluster enables the beta feature. Node-dependent options remain explicit and
never weaken the baseline; API-version detection alone cannot prove node support.

Enforce Restricted Pod Security on the dedicated namespace using the cluster
minor version, for example:

```sh
kubectl label namespace auth --overwrite \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.37 \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/audit-version=v1.37 \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/warn-version=v1.37
```

Use the actual namespace and minor version. Review and requalify these labels
when upgrading the cluster, because admission requirements can evolve. Labels
apply to every workload in the namespace, including Jobs and managed Keycloak
pods; review existing workloads before enforcing them. Helm does not change
administrator-owned namespace labels or install admission/CNI components.

### Installation steps

1. Select an immutable operator image digest from a verified delivery. Check
   source revision, image provenance and the Attest receipt against independent
   signer/TSA trust. A digest alone proves content identity, not publisher identity.
2. Choose a dedicated watch namespace and a single owner for each provider
   object. Provision an existing Keycloak service-account Secret with
   `client-id` and `client-secret`, granting only the provider operations needed.
   Configure `controlPlane.fleetAuthorityRealm` and `authorizedClients` for the
   actual authority realm; do not treat their defaults as discovery.
3. Configure verified HTTPS and certificate trust for Keycloak. The default
   URL in the values file is a compatibility default; review it before deployment.
4. Supply exact Kubernetes API Service and endpoint addresses, their ports,
   DNS destinations, and Keycloak pod labels or external addresses. A CNI must
   enforce NetworkPolicy; an accepted YAML manifest alone is not enforcement.
5. Review the rendered workload, RBAC and network policies before installation.
   The pod runs without root, privilege escalation or BPF capabilities, with a
   read-only root filesystem. Keep image-policy administration outside its account.

For an existing Keycloak service in the `auth` namespace, the following values
illustrate the required fields. Replace every placeholder, confirm the actual
labels/Service/target ports, and pre-provision the referenced Secrets:

```yaml
profile: standard
image:
  digest: "sha256:<verified-operator-image-digest>"
keycloak:
  enabled: true
  url: https://keycloak.auth.svc.cluster.local:8443
  credentialsSecret: keycloak-ops-credentials
  caSecret: keycloak-admin-ca
  caKey: ca.crt
controlPlane:
  fleetAuthorityRealm: hanko
  authorizedClients:
    - hanko-dashboard
networkPolicy:
  enabled: true
  kubernetesAPIServiceCIDRs:
    - "<kubernetes-api-service-ip>/32"
  kubernetesAPIEndpointCIDRs:
    - "<kubernetes-api-endpoint-ip>/32"
  kubernetesAPIEndpointPorts: [443, 6443]
  keycloakNamespace: auth
  keycloakSelector:
    app: keycloak
  keycloakPorts: [8443]
```

Use `/128` for IPv6 API destinations. Add the actual Keycloak target port if
it differs from the Service port. For an external provider, use
`keycloakSelector: null`, exact `keycloakExternalCIDRs` and
`keycloakExternalPorts`. For another namespace, configure its selector boundary.
Per-instance Admin API Secrets use `HANKO_KEYCLOAK_URL`, `HANKO_KC_CLIENT_ID`
and `HANKO_KC_CLIENT_SECRET`; `spec.tlsCARef` supplies their private CA separately.

```sh
helm template hankoshell-operator ./charts/hankoshell-operator \
  --namespace auth --values operator-values.yaml
```

After reviewing the render, apply the CRDs and install as described in the
[README](../README.md#deployment). Verify that the operator can reach its API
and provider, and that unauthorized ingress/egress is denied. Test the actual
CNI, DNS and API endpoint routing on each target cluster; Kubernetes and Cilium
allow policies are additive when other policies select the same pods.

If theme Jobs or managed provider image updates are enabled, pre-provision
the image-policy ConfigMap and install the independent
[admission policy](../config/security/operator-image-policy-admission.yaml).
It initially binds the `auth` namespace; adapt and review that binding for
another namespace. An empty image policy denies new workload image execution.

## Enterprise profile

Set `profile: enterprise` with `hub.enabled`, `continuum.enabled`, baseline
NetworkPolicy and a full image digest. Continuum is a separately installed
node DaemonSet; the operator never receives its WireGuard private keys or
network administration capabilities.

Configure the exact HTTPS Hub origin, private relay IP and Hub TLS hostname.
The client dials that relay directly, verifies its certificate with TLS 1.3,
disables environment proxies and rejects redirects. CRDs cannot switch it to
another Hub endpoint or direct synchronization. Established credentials must
have tenant/cluster identity and an unexpired deadline. Keycloak, organization
projection and supervision clients also require verified TLS 1.3; configure
their real TLS ports and trust stores.

Initial enrollment requires a single-use token, a separately configured HTTPS
bootstrap endpoint and exact bootstrap CIDRs. After enrollment, retain the
tenant ID and credential Secret, remove the token and clear bootstrap CIDRs.
There is no automatic public synchronization fallback.

Qualify the Continuum link and selected network policies on the target cluster.
The profile does not issue workload certificates, enable mTLS on every
integration, or promote mesh-policy auditing to enforcement. Admission of
Attest-approved operator images is a separate administrator-owned control.

## Upgrade and rollback

Clusters below 1.35 must be upgraded and qualified before installing this chart;
the previous unrestricted `>=1.30` declaration did not establish that support.
When rolling back optional AppArmor or user namespace settings, disable the
corresponding `hardening` values and review the resulting pod rollout. Keep the
mandatory baseline and namespace admission controls enabled.

Review the [changelog](../CHANGELOG.md), CRD schema changes, ownership and
finalizers. Preserve the previous image digest, chart, values and provider
backup. Helm does not upgrade or roll back CRDs automatically; an older schema
must remain compatible with existing objects before it can be restored.

For installations using the legacy platform email connector, upgrade the
hankoShell API first, select its vault, save the provider reference and pass
an explicit Graph delivery test. Disable `azureKeyVault` and
`networkPolicy.externalEmailEgress` on the new operator. The deprecated CRD
retains its spec but no longer performs delivery or reads vault credentials.

To roll back that migration, restore the previous API/operator images and
charts, the previous API configuration with `keyVaultSecretName`, and the prior
operator vault identity and HTTPS egress values. Test readiness and delivery
again. API provider credentials and Keycloak's authentication SMTP remain
separate responsibilities.

Validate configuration and data restoration before enabling snapshot data
Jobs. PostgreSQL/PVC backup behavior remains installation-specific; this
release does not qualify portable backup/restore across cloud providers.
