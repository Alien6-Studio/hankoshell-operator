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

### OCI delivery evidence

Review the [final-image vulnerability gate and exception policy](../SECURITY.md#final-oci-image-vulnerability-gate)
alongside source govulncheck. Required CI scans the final AMD64/ARM64 runtime
filesystems, including the separately compiled cosign executable. The release
copies that same OCI archive without rebuilding, preserves BuildKit SBOM and
provenance, and selects its signed index digest in the chart. Do not install
`staging-*` references; only reviewed release references have passed every delivery
gate, including Continuum Attest. Verify the exact digest and independent signer
identity, not just a human-readable tag.

`oci-security.json` records the index and per-platform/configuration digests,
scanner version/binary hash, database hash/metadata, scan time, policy hash,
report hashes and decision. The complete reports and policy are checksum-signed
and included in the Attest delivery receipt. A scan is a point-in-time database
assessment; new vulnerabilities may be discovered after release. The fixable-only
threshold retains unfixed and lower-severity findings for review and does not
certify an image as vulnerability-free.

BuildKit's SBOM is inventory and its provenance is producer build evidence.
The vulnerability report evaluates detected inventory; the Sigstore signature
authenticates a digest; Attest binds and timestamps the verified delivery files.
The OCI index retains BuildKit's platform-linked evidence, including producer
predicate formats whose pre-publication subject array may be empty. The index
annotations establish that link; the signed index authenticates the complete
graph. Attest does not replace scanning or supervise the build.

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

### Hub remote commands

Hub can propose an operator update through a heartbeat response. Before changing
its Deployment, the operator requires a local `operator-update` approval matching
the exact image digest, release version and source revision, then verifies the
publisher signature with the pinned runtime cosign. It preserves its current
image repository. Missing approval, revoked approval, failed verification or a
concurrent Deployment change prevents the patch. Already-pinned images are checked
again; a version string alone does not authorize an update.
The Hub reference version must match the reviewed SemVer release, such as `0.1.0`.

Configure `imageVerification.policyConfigMap: hanko-image-policy`, the independent
[admission policy](../config/security/operator-image-policy-admission.yaml) and
exact `imageVerification.egressCIDRs` for registry and Sigstore access. Keep policy
administration outside the operator account and Hub's credentials.

Before adding an approval, verify the delivery's scan evidence, Sigstore signatures
and Continuum Attest receipt against independently trusted keys and TSA. Confirm
that its image digest and source revision match the approval. Runtime verification
checks the image signature; it does not fetch or verify the Attest receipt itself.
The local approval records the administrator's reviewed delivery decision.

For official releases, `policy.json` in that ConfigMap can contain the following
approval. Replace the digest and source placeholders with the reviewed values:

```json
{
  "version": 1,
  "approvals": [{
    "purpose": "operator-update",
    "image": "ghcr.io/alien6-studio/hankoshell-operator@sha256:<verified-digest>",
    "revision": "<full-source-revision>",
    "release_version": "0.1.0",
    "certificate_identity": "https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/v0.1.0",
    "certificate_oidc_issuer": "https://token.actions.githubusercontent.com"
  }]
}
```

Only the exact official release workflow/tag identity and GitHub issuer are
accepted for keyless operator approvals; certificate and transparency checks stay
enabled. A separately signed mirror can instead use `key_file` for a mounted
public `.pub` key, omitting both certificate fields. It still needs the exact
version, digest and source revision. Remove old approvals to withdraw update or
rollback authorization. Protect the policy independently of Helm and Hub access.

Remote decommission requires nonzero `requestedAt` and `deadline`, with
`requestedAt <= now < deadline` and `requestedAt < deadline`. Missing, future,
reversed or expired windows are rejected before cleanup. Keep operator and Hub
clocks synchronized. The deadline also bounds execution: no new cleanup mutation
or confirmation starts after expiry. The operator reports failures through its
regular heartbeat; a new command needs a new valid authorization window.

Cleanup is not transactional. A deletion accepted before expiry can finish later,
and Kubernetes garbage collection cannot be cancelled by this deadline. If expiry
interrupts cleanup after Hub confirmation, the operator logs remaining resources
for manual removal; the surrendered credential cannot re-authorize another run.

### Instance administrative ownership

`HankoKeycloakInstance` probes its provider without changing master security
settings or its administrative credential by default, in all three modes.
Set `spec.hardenMasterRealm: true` or `spec.rotateAdminCredentials: true` only
when assigning those tasks to the operator, with the permissions described in the
[Keycloak permission model](keycloak-permissions.md). Without rotation enabled,
the administrator owns credential age, rotation and revocation.

Managed mode authorizes provisioning the declared workload. Adopted mode observes
the referenced Deployment; `spec.adopted.publishDiscovery: true` separately
authorizes discovery labels/annotations on its referenced Service. Extra account
permissions do not turn these optional writes on. Apply the new CRD before
upgrading and explicitly enable the operations an existing instance should retain.
Reserve instance spec and AdminRef changes for provider administrators. These
flags express requested operations; they do not reduce the roles on a supplied
Keycloak credential or replace Kubernetes access controls.

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

Every Keycloak HTTP response passes through the same bounded reader before
client methods see it, including token acquisition, credential rotation,
authorization, mappers, groups, organizations and write acknowledgements.
The per-response budgets are **1 MiB** for Admin representations, **64 KiB** for
tokens/client secrets and **8 KiB** for non-2xx responses, in both profiles.
They apply to decompressed bytes; missing or understated `Content-Length` cannot
bypass them. The reader detects overflow with one extra byte, closes the original
stream and rejects incomplete reads instead of accepting a valid JSON prefix.
Tokens and rotated secrets also require a complete JSON document, without trailing
data. No partial token is cached or partial representation returned.

Oversize responses report `ErrResponseTooLarge` with their HTTP status and byte
budget; broken streams report `ErrResponseRead` without response contents.
Large installations must fit these budgets on each requested page/representation;
there is no silent truncation, automatic limit relaxation or new pagination of
otherwise unpaged APIs. The existing ten-second HTTP timeout remains in effect.
These limits bound individual network reads, not the whole reconciliation's
memory or object count. A response read failure cannot undo a provider write
already accepted by Keycloak; verify provider state before manual retry.

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

### Managed Keycloak transport

`HankoKeycloakInstance` with `spec.mode: managed` provisions a native HTTPS
listener. Set `spec.managed.tlsSecretRef` to a **separate same-namespace
`kubernetes.io/tls` Secret** with `tls.crt` and `tls.key`. It is mounted read-only;
the key is not imported as an environment variable. A missing Secret, invalid or
mismatched key pair, expired/not-yet-valid certificate or certificate that does
not cover the AdminRef endpoint hostname blocks infrastructure changes.
The operator does not issue certificates. Provision and renew them through your
certificate manager and keep serving certificates and client trust in agreement.

The AdminRef `HANKO_KEYCLOAK_URL` must be HTTPS and match the certificate hostname.
For direct Service access, use `https://<instance>.<namespace>.svc:8443` with that
DNS name in the certificate SAN. Public CA trust needs no `spec.tlsCARef`; a
private CA needs a separate Secret with `ca.crt` referenced by `spec.tlsCARef`.
The serving Secret and client CA Secret have different purposes. The client
still verifies the full certificate chain and hostname on every connection.

```yaml
apiVersion: hanko.sh/v1alpha1
kind: HankoKeycloakInstance
metadata:
  name: keycloak
  namespace: auth
spec:
  mode: managed
  adminRef:
    name: keycloak-ops-credentials
  tlsCARef: keycloak-client-ca # Omit for a publicly trusted serving certificate.
  managed:
    image: registry.example/keycloak@sha256:<reviewed-digest>
    database:
      name: keycloak-database
    tlsSecretRef: keycloak-serving-tls
```

Supply a digest-approved, signed **optimized** Keycloak image built with
`KC_HEALTH_ENABLED=true`, `KC_HTTP_RELATIVE_PATH=/`,
`KC_HTTP_MANAGEMENT_RELATIVE_PATH=/` and the database provider matching the
database Secret. The operator uses `start --optimized`: runtime augmentation
cannot write to the read-only image filesystem. Managed endpoints use the root
context path; a non-root AdminRef path is rejected. Other modes still support
the documented context paths. These are Keycloak build-time settings, so changing
them requires rebuilding and approving the image. Listener, TLS protocol and
hostname are explicit runtime arguments; a conflicting Secret environment
variable cannot turn the IAM HTTP listener back on. See Keycloak's
[optimized container build](https://www.keycloak.org/server/containers) and
[serving certificate configuration](https://www.keycloak.org/server/enabletls).

The managed Deployment, ClusterIP Service and IAM ingress rules use TCP/8443.
The Service's `hanko.sh/endpoint-template` announces the validated AdminRef URL
to API discovery, preserving HTTPS and the certificate hostname rather than
falling back to an inferred HTTP Service URL. Configure private CA trust in the
API separately when it connects to that endpoint.
Standard permits TLS 1.2/1.3; enterprise permits only TLS 1.3. Default ingress
peers remain the selected API/operator pods in the instance namespace and the
selected Traefik pods in `kube-system`. Configure the operator's Helm egress
namespace, pod selector and port to match this instance. A cross-namespace
operator or a different proxy requires an administrator-owned narrow ingress
rule; no cluster-wide ingress is added automatically.

Readiness/liveness use HTTP `/health/ready` and `/health/live` on the separate
management listener, TCP/9000. This listener has no Service and no allowed pod
ingress in the generated policy; kubelet probes are node traffic. It carries
health details, not the IAM/Admin API or administrative credentials. NetworkPolicy
requires an enforcing CNI and does not restrict the hosting node. Validate node
probes and networking in the installation. A TLS-terminating ingress does not
replace native Keycloak HTTPS; configure and verify its backend TLS separately.

**Migration:** update the CRD and managed configuration together. An old HTTP-only
managed declaration does not silently acquire a certificate or change its URL.
Configure the serving Secret, HTTPS AdminRef URL and client CA trust, then align
the ingress/backend and Helm egress ports. Invalid transport leaves existing
workloads untouched and reports `TransportError`. Switching ports can interrupt
traffic until those dependent configurations are updated.

For an intentionally trusted HTTP installation, standard requires **both**
`spec.managed.allowInsecureHTTP: true` and the process-wide
`keycloak.allowInsecureHTTP: true`, with an HTTP AdminRef URL and no
`spec.managed.tlsSecretRef` or `spec.tlsCARef`. Deployment, Service and IAM ingress
then use TCP/8080. This has the same plaintext credential/traffic exposure as the
administrative HTTP exception above. Enterprise refuses this combination.

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
hostile tenants. Master hardening requires `spec.hardenMasterRealm: true` and
master `manage-realm`; a requested operation must succeed before Ready. Without
that opt-in, administrators enforce the baseline independently. Keycloak 26.7.5 allows `view-clients` to read secrets;
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
installation acceptance tests. No runtime version rejection is added.
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

If theme Jobs, managed provider image updates or Hub self-updates are enabled, pre-provision
the image-policy ConfigMap and install the independent
[admission policy](../config/security/operator-image-policy-admission.yaml).
It initially binds the `auth` namespace; adapt and review that binding for
another namespace. An empty image policy denies new workload image execution.

## Metrics and Prometheus

`metrics.enabled: false` is the default and disables the manager metrics server
(`--metrics-bind-address=0`), container port, Service, scrape annotations,
ServiceMonitor and metrics ingress. The separate health probe port 8081 remains.
The binary's default is also `0`; direct deployments must explicitly configure
their metrics bind address and equivalent network controls.
The global disable also overrides a retained `serviceMonitor.enabled: true`:
no monitor is created and no Prometheus API is needed while metrics are off.

`metrics.enabled: true` exposes HTTP `/metrics` on TCP/8080 through the
release-owned ClusterIP Service. With `metrics.serviceMonitor.enabled: false`,
pod annotations advertise scraping; annotation discovery must already be configured
in Prometheus. With `true`, the chart creates a ServiceMonitor selecting only
that Service in the operator namespace and suppresses pod scrape annotations.
The Prometheus Operator API must be installed. Configure Prometheus to discover
ServiceMonitors in that namespace and match their metadata labels; use
`metrics.serviceMonitor.labels` for an existing discovery filter. Those labels
cannot replace chart identity labels. The chart does not install monitoring
components or change Prometheus's outbound policies.

Default-deny NetworkPolicy remains enabled. Enabling metrics with it requires
both source selectors, regardless of the discovery method:

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    labels:
      release: prometheus-stack
  networkPolicy:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: monitoring
    podSelector:
      matchLabels:
        app.kubernetes.io/name: prometheus
        prometheus: platform
```

Replace the namespace and pod/discovery labels with your actual configuration.
Selectors accept only nonempty exact `matchLabels`. The namespace must be pinned
by its immutable `kubernetes.io/metadata.name`; arbitrary namespace labels alone,
expression-only selectors, wildcards and IP/CIDR sources are rejected. The
rendered rule has **one peer containing both selectors**, and only TCP/8080.
This conjunctive source constraint avoids the cluster-wide grant produced by
empty selectors or separate namespace/pod peers. See the Kubernetes
[NetworkPolicy selector semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors).
Other pod ingress remains denied by this policy. The optional Cilium egress
policy preserves this baseline ingress and grants no additional source.

For offline rendering with ServiceMonitor enabled, add
`--api-versions monitoring.coreos.com/v1/ServiceMonitor` to `helm template`.
Inspect the Deployment flags/ports, Service, ServiceMonitor and NetworkPolicy.
Check the actual Prometheus pod labels, its monitor discovery filters and its
own egress policy. On each target installation, verify scraping from the selected
pods and denial from an unrelated pod in the same namespace and from another
namespace. The API-server tests validate admission and policy shape, not CNI
enforcement or a running Prometheus deployment.

Metrics may disclose operational details. They use unauthenticated plaintext
HTTP; these selectors restrict reachability and provide neither encryption nor
cryptographic authentication. Control who can deploy/relabel pods in the selected
namespace. Review other additive allow policies, node/host-network behavior and
your CNI's enforcement. Disabling `networkPolicy.enabled` in standard mode means
this chart provides no ingress restriction; enterprise rejects that opt-out.

**Migration and rollback:** the old `metrics.enabled` only created a
ServiceMonitor while the listener, Service and annotations were always active.
Retaining ServiceMonitor discovery now requires both enable flags, the explicit
Prometheus identity when NetworkPolicy is on, and matching discovery labels.
The old flag alone fails closed with default networking. Default `false` now
removes that exposure. Service names, selectors and TCP/8080 remain compatible.
An older chart/image restores its previous exposure/defaults; inspect its render
and network controls before rollback.

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

## Privileged lifecycle behavior and limits

The default Role permits reconciliation and workload Jobs in the release namespace,
including access to Secrets there. The watch namespace is a trust boundary:
do not allow hostile tenants to create operator CRDs or credentials in it.
The default cluster-scoped readers permit node `get` and named `kube-system`
Namespace `get` for identity discovery. Hub decommission also permits `get`,
`patch` and `delete` on the release's two named reader ClusterRoles/bindings.
They do not confer general cluster administration.

Optional mesh audit reads Services (`get`) in configured egress namespaces and
writes its protected projection in the chosen transport namespace. Optional
transport decommission can delete the named VPN DaemonSet. Its Helm bookkeeping
Role needs namespace-wide Secret `get/list/delete`, because Helm versions have
generated Secret names. Label selection in controller code is not an RBAC
restriction; use a dedicated transport namespace with no unrelated Secrets.

Instance administrative rotation is disabled unless
`spec.rotateAdminCredentials: true`; `HANKO_KC_SA_MAX_AGE` (90 days by default)
then controls its schedule. This needs master client authority and configured
rotation audit delivery. The chart's default Keycloak connection does not require
this CRD. Follow the [rotation guidance](keycloak-permissions.md#credential-rotation).
Audit failure can report degradation after a secret has already changed.

### Database snapshot Jobs

Snapshots serialize supported operator configuration into a ConfigMap without
running a database workload by default. `spec.includeData: true` requires managed
mode with a database reference and all three explicit backup settings:

```yaml
apiVersion: hanko.sh/v1alpha1
kind: HankoSnapshot
metadata:
  name: keycloak-backup
  namespace: auth
spec:
  instanceRef: keycloak
  includeData: true
  backupPVC: keycloak-backups
  backupImage: registry.example.org/iam/pgdump@sha256:<reviewed-image-digest>
  backupSecretRef: keycloak-backup-credentials
```

Replace the digest placeholder with the full reviewed SHA-256. There is no image
default or tag fallback. Configure `imageVerification.policyConfigMap` with the
publisher's public key and an exact approval in its `policy.json`, for example:

```json
{
  "version": 1,
  "approvals": [{
    "purpose": "database-backup",
    "image": "registry.example.org/iam/pgdump@sha256:<reviewed-image-digest>",
    "revision": "<reviewed-source-commit>",
    "key_file": "backup-publisher.pub"
  }]
}
```

The publisher must sign that digest with the configured key and the
`hanko.git.revision` annotation. The operator verifies the signature live before
creating the credential-bearing Job, then rechecks local approval/key revocation.
Theme, managed-Keycloak and operator-update approvals cannot authorize backups.
Missing approval, mutable/unapproved reference, missing key, failed verification
or registry unavailability fails closed with `UntrustedBackupImage`. No Job is
submitted on those paths. Existing Jobs must be controlled by this snapshot and
match its image, command, credentials, volumes and security settings; even a
completed Job is not accepted by name alone. Changes to the recorded Job template,
including extra containers or altered execution settings, fail this check.
An approval removal does not kill
an already-running pod; suspend/delete it and revoke its DB credential during an
incident. Kubernetes admission and administrator control remain necessary.

Create the backup Secret outside committed manifests. It must differ from the
instance's administrative, managed database and serving TLS Secrets. Grant its DB
identity only the connection/read privileges needed to dump the intended database;
the operator does not inspect or reduce PostgreSQL grants. The Job references only
`PGHOST`, `PGDATABASE`, `PGUSER` and `PGPASSWORD` (required nonempty), plus optional
`PGPORT` and `PGSSLMODE`. Other Secret keys are not imported. Keycloak `KC_DB_*`
settings are not translated. This check separates Secret references, not database
identities: administrators must provision separate, appropriately limited DB
credentials. Restrict Secret and snapshot writes to trusted administrators.

The reviewed image must provide `pg_dump` on PATH and run under UID/GID **70**
with a read-only root filesystem; there is no root fallback. The Job drops all
capabilities, forbids privilege escalation, uses `RuntimeDefault` seccomp and has
no automatically mounted Kubernetes service-account token. Only the backup PVC
and scratch `/tmp` are writable; filesystem group 70 must work with the selected
CSI/storage driver. Required Kubernetes CI verifies the generated Job round-trip
and its pod's Restricted admission, not execution on a production database.

The backup image is separate from the scanned operator OCI artifact. Before
approving it, verify its own vulnerability scan, source/provenance, publisher
signature and supported PostgreSQL client/server versions. A valid signature
does not prove an image is safe. Configure independent default-deny networking
and narrow DB egress for the Job; the Helm operator policy is not a backup-pod
network policy. Database transport depends on the selected libpq settings and
image trust store; signature verification does not encrypt DB traffic. Set and
qualify certificate-verifying database TLS in the installation.

**Migration:** apply the updated CRD, configure these explicit fields and approval,
and create a new snapshot. Old mutable Jobs are not adopted or silently replaced;
inspect and stop them before enabling the new path. Previously terminal snapshots
remain historical records, not retroactive evidence of verified execution.
Portable backup/restore, consistency and recovery across database versions or
cloud providers are not qualified. `HankoOperation.snapshotBefore` creates only
a configuration snapshot and does not establish a database rollback point.

`Clone` creates an external instance alias reusing the source administrative
connection and imports supported configuration; it does not provision a new
database. `clone.includeData` has no effect in 0.1.0. A target namespace outside
the release namespace is outside the default watch/RBAC scope. `DBSwitch` changes
the database Secret reference without migrating data. Operation `dryRun` skips
planned steps; it does not validate provider compatibility or recoverability.
These operations are not a tested disaster-recovery workflow.

## Release rehearsal and publication

0.1.0 is a normal SemVer release in initial development. The experimental
`hanko.sh/v1alpha1` APIs may change across minor releases before 1.0. Artifact Hub
uses `prerelease: false`; the workflow creates a normal GitHub **draft**, with
curated notes extracted from the tracked CHANGELOG release overview. Publication
of that draft remains a separate manual action. The tag must already exist on
protected main; the workflow does not create tags.

Required CI builds one AMD64/ARM64 OCI archive with BuildKit SBOM/provenance,
scans its exact manifests, and passes that immutable artifact ID to the release
rehearsal. The rehearsal shares packaging code with publication: chart metadata,
generated CRDs, digest-pinned values, curated notes, artifact names and checksums
are checked. Native pinned cosign signs the checksum payload with an ephemeral
local key; OpenSSL verifies the signature and rejects tampering. Native Continuum
Attest signs and timestamps the delivery using an ephemeral Ed25519 identity and
loopback RFC 3161 TSA. All five native checks and a tamper rejection must pass.

To reproduce with the **fresh archive/evidence from the OCI security job**:

```sh
bash scripts/install-cosign.sh /tmp/hankoshell-rehearsal-tools/cosign
bash scripts/install-attest.sh /tmp/hankoshell-rehearsal-tools/attest
make release-dry-run REVISION="$reviewed_revision" DIGEST="$scanned_digest" \
  OCI_ARCHIVE="$archive_path" OCI_EVIDENCE="$evidence_directory" \
  DRY_RUN_OUTPUT="$fresh_output_directory" \
  COSIGN=/tmp/hankoshell-rehearsal-tools/cosign \
  ATTEST=/tmp/hankoshell-rehearsal-tools/attest OPENSSL="$(command -v openssl)"
```

Use OpenSSL 3, pinned Helm 3.17.0 and the Python dependencies in
`scripts/requirements.txt`. The report is explicitly `publishable: false`; its
keys, TSA and Artifact Hub ID are fixtures. No private key is retained in its
artifacts. It never pushes a registry reference, creates a tag/GitHub Release or
changes Artifact Hub. The local signature proves payload binding, **not** GitHub
OIDC/Fulcio/Rekor trust. Production image signatures remain keyless Sigstore with
issuer `https://token.actions.githubusercontent.com` and exact certificate identity
`https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/v0.1.0`.

Before publication, maintainers must configure the real Attest signing secret,
trusted public key/ID, RFC 3161 endpoint and pinned TSA certificate in the
reviewed `release` environment, register the OCI chart in Artifact Hub and set
its assigned repository UUID, and verify public registry access. See the README
release configuration. The rehearsal does not qualify these external settings.
Artifact Hub Verified Publisher establishes ownership, not vulnerability absence
or a chart signature. The named Attest key link is not Helm OpenPGP `.prov` signing.

Publication consumes the same scanned archive without rebuilding, stages it under
a non-release reference, verifies real image/blob Sigstore signatures and strict
Attest delivery evidence, then promotes the digest, chart and catalog metadata.
Only after that does it create the GitHub draft. These network writes are not an
atomic transaction: a later failure may leave already verified packages available.
Inspect exact registry digests and existing drafts before retrying; do not rebuild
or substitute a different digest to work around a failed gate.

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
