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

### Keycloak administrative transport

Administrative service-account credentials, bearer tokens and Keycloak Admin
API requests/responses are security-sensitive. Verified HTTPS is required by
default in every operator Keycloak client, including default, per-instance,
Import/Observe, pending credential rotation and dedicated tenant connections.
The chart defaults to `https://keycloak.auth.svc:8443`; this is a configurable
Service placeholder, not discovery of the installation's endpoint or trust.
An enabled Keycloak with an empty URL fails Helm rendering. Disabled/spoke
installations need no default URL but still enforce the policy for any dedicated
connection they register.

| Transport | Standard | Enterprise | Trust configuration |
| --- | --- | --- | --- |
| HTTPS, public CA | Accepted | Accepted | System CA roots; no custom CA Secret required |
| HTTPS, private CA | Accepted | Accepted | `keycloak.caSecret`/`caKey`, or per-instance `spec.tlsCARef` |
| HTTP, default settings | Rejected before credentials are sent | Rejected | No implicit exception for an absent CA Secret |
| HTTP, explicit `keycloak.allowInsecureHTTP: true` | Accepted for intentionally trusted environments | Rejected | No TLS protection; a custom CA configuration is rejected |

Standard uses verified TLS >=1.2; enterprise additionally requires TLS 1.3 and
its existing origin/proxy restrictions. TLS verifies certificate trust and the
endpoint hostname. The dedicated private CA is confined to its Keycloak client;
it does not change trust for other integrations. Invalid or missing configured
CA data fails rather than falling back. Redirects are refused. There is no
`insecureSkipVerify` or equivalent option.

URLs must be HTTP(S) origins with a DNS/IPv4 host or bracketed IPv6 literal and
an optional unescaped context path such as `/auth`. Userinfo (even username-only),
queries, fragments (including empty delimiters), malformed/out-of-range ports,
encoded path segments, repeated separators and `.`/`..` path segments are
rejected. Put credentials in the existing Secret, never in the URL. Helm and
Go exercise the same endpoint fixture contract; instance clients retain the
existing cloud metadata endpoint denial.

For pre-1.0 migration, review stored release values before upgrade. Old HTTP
values are not converted to HTTPS or implicitly accepted. Prefer configuring
verified HTTPS and the appropriate public/private trust, then set exact Service,
target and external egress ports. The default in-cluster policy now uses 8443;
external HTTPS remains 443 unless configured otherwise.

If an administrator intentionally accepts HTTP on an independently trusted
network, the required standard-profile acknowledgement is:

```yaml
profile: standard
keycloak:
  url: http://keycloak.auth.svc:8080
  allowInsecureHTTP: true
  credentialsSecret: keycloak-ops-credentials
networkPolicy:
  keycloakPorts: [8080]
```

This exception provides **no transport confidentiality, integrity or server
authentication** for the administrative connection. A party able to intercept
or alter that path can capture credentials/tokens and read or modify traffic.
NetworkPolicy limits reachable destinations; it does not encrypt or authenticate
HTTP. A service mesh or TLS-terminating proxy must independently secure every
hop; this flag does not install or verify that protection. Verified HTTPS does
not protect credentials in a compromised operator/provider or against an
administrator holding those credentials.

For a non-Helm deployment, only the exact environment value
`HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP=true` acknowledges HTTP; unset/`false` denies
it and other spellings fail configuration. The chart owns this environment value
and `HANKO_KEYCLOAK_URL` and rejects overrides through `env`. The acknowledgement
is administrator-controlled and process-wide, including endpoints from instance
and tenant Secrets; it is not granted by a CRD. Enterprise ignores the HTTP
allowance and still requires HTTPS. Remove the exception after migration.
Keep existing authentication and least-privilege controls: transport encryption
does not reduce the service account's granted administrative authority.

### Keycloak compatibility

hankoShell Operator **0.1.0 is qualified against Keycloak 26.8.0 and 26.7.5**
using the HTTPS Admin API v1 and service-account `client_credentials` flow.
The official images are pinned by immutable multi-architecture index digests
in the [qualification fixture](../internal/controller/keycloak_fixture_test.go).
Both versions run in required PR/release CI and weekly CI; the aggregate required
check fails on either matrix failure or startup failure. Qualification is a
compatibility contract, not a recommendation to retain a vulnerable patch.

| Version | 0.1.0 qualification |
| --- | --- |
| 26.8.0, 26.7.5 | Qualified by the real Admin API suite |
| Other 26.x patches | May work; unqualified until the same suite passes |
| <=25.x or future major lines | Unsupported by this contract pending explicit qualification |

Tests run real controllers against an HTTPS-only disposable Keycloak with
verified certificates, hostname validation and TLS 1.3. They cover realm create,
update, repeated reconciliation and deletion; SPA/web/M2M clients, redirect and
post-logout URLs; realm/client/composite roles; IAM profiles, TOTP required-action
and OTP settings, password/session/brute-force policy; OIDC broker/mapping paths;
credential projection, recovery and rotation without repeated rotation; drift
restoration; unrelated client/role/provider preservation; finalizer ordering;
and read-only import/observe. Admin write-event history must remain unchanged
during observation. CRD specs/status, controller logs and Kubernetes events
must contain no credential values or bearer tokens.

The fixture creates a temporary bootstrap administrator only for setup, drift
injection and state verification. Normal reconcilers use a dedicated master
service client with target-scoped `manage-realm`, `manage-clients`, `manage-events`,
`manage-users` (MFA/session enforcement) and `manage-identity-providers` (brokers).
Import/Observe runs under a separate `view-realm`, `view-clients`,
`view-identity-providers` identity. Capability tests prove the three-role common
profile, role-omission failures and unauthorized-operation denials. An isolated
creator account qualifies `create-realm` and Keycloak's native broad scoped grants.
No normal operator identity has master `admin`, `realm-admin` or `impersonation`.

Follow the **[tested Keycloak permission model](keycloak-permissions.md)** when
provisioning credentials. The operator no longer creates master proxy clients or
self-grants administrative roles. Anyone authorized to write managed CRDs can
exercise its provider authority; do not treat these objects as safe for mutually
hostile tenants. Master hardening remains an attempted optional operation, reported
in `MasterRealmHardened`; without master `manage-realm`, administrators enforce
that baseline independently. Keycloak 26.7.5 allows `view-clients` to read secrets;
26.8.0 rejects that read without `manage-clients`. Import/Observe omits those
credentials on both. Target-scoped master credentials do not receive the
server version on either qualified version, so `status.keycloakVersion` can be empty.
Do not broaden master permissions merely to fill this diagnostic field.

Unmanaged clients, roles and brokers survive child reconciliation/deletion.
Deleting a managed realm is an explicit destructive ownership boundary: once
managed applications/service accounts/issuers are gone, Keycloak deletes the
realm and **all contents**, including objects added outside the operator. Separate
unrelated realms and master configuration survive this path. Keep backups and
review ownership before deletion; neither reverting the operator nor the chart
restores deleted provider state or previously rotated credentials.

The suite uses Keycloak's disposable `dev-file` database in production server
mode and a fake Kubernetes client. It does not qualify PostgreSQL, clustering,
browser login/MFA challenges, actual upstream federation, Admin API v2, custom
providers/themes, end-user resource-server authorization decisions, managed/adopted instance
rollouts, backups/restores, or cloud/CNI/storage behavior. Those surfaces require
installation acceptance tests. No API schema, chart/app version or provider
migration is changed by this qualification; no runtime version rejection is added.
The application discovery probe still uses system CA trust: this suite's private
test CA intentionally leaves its `Operational` condition false without bypassing
certificate verification.

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
3. Configure verified HTTPS and certificate trust for Keycloak. Replace the
   default Service URL with the actual endpoint; use system trust for public CAs
   or the dedicated CA Secret for private CAs. Review the [transport migration](#keycloak-administrative-transport).
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
Use a [dedicated service account with the tested target-scoped permissions](keycloak-permissions.md),
not `realm-admin`. Per-instance Admin API Secrets use `HANKO_KEYCLOAK_URL`, `HANKO_KC_CLIENT_ID`
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
