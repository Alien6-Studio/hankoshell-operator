# hankoShell Operator chart

Helm chart for declarative Keycloak IAM configuration with hankoShell Operator.
Version 0.1.0 is a normal SemVer release in initial development.
The chart installs 16 experimental `hanko.sh/v1alpha1` CRDs. These APIs may change
between minor versions. All controllers are registered; integration flags
configure their connections to optional services.

Kubernetes **1.35–1.37** and Linux nodes are the qualification window. CI uses
real API-server/etcd fixtures to check CRDs, server-side apply, RBAC and Restricted
admission on each minor. Future minors and upstream alpha/beta/RC builds are rejected
until qualified. Install the latest provider security patch; fixed CI fixtures
do not certify nodes, CNI/CSI or cloud-provider behavior.
Required CI additionally installs this chart with the scanned operator image on
kind Kubernetes 1.37.0 and real HTTPS Keycloak 26.8.0, then tests reconciliation,
restart recovery and deletion. kindnet does not enforce NetworkPolicy; this test
does not establish production network or database qualification.

`hardening.appArmor: true` requests `RuntimeDefault` on AppArmor-enabled nodes.
`hardening.userNamespaces: true` sets `hostUsers: false` and requires Kubernetes
**>=1.36**, Linux **>=6.3**, idmap-capable filesystems and compatible runtimes.
The chart rejects user namespaces on 1.35 and invalid or unknown hardening options.
The baseline non-root/seccomp/capability/filesystem protections remain mandatory.
See the [compatibility matrix and namespace admission configuration](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#kubernetes-compatibility-and-hardening).

Provision a **[dedicated Keycloak service account using the tested permission model](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/keycloak-permissions.md)**.
The existing-realm profile needs target `manage-realm`, `manage-clients` and
`manage-events`; optional capabilities have additional or inherited authority.
Keep secrets outside committed values and review native realm-creation grants.

Real HTTPS Admin API v1 qualification covers Keycloak **26.8.0 and 26.7.5** only.
Other patches and major lines are unqualified. Hub/Continuum integrations are
optional; standalone Keycloak reconciliation does not depend on them. See the
[qualification limits](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#keycloak-compatibility)
and project website [hanko.sh](https://hanko.sh).

Instance `spec.hardenMasterRealm` and `spec.rotateAdminCredentials` default to
`false`, including in managed mode. Set them explicitly only when the operator
owns those tasks and has the documented master permissions. Referencing an adopted
Service does not authorize changes to it; use `spec.adopted.publishDiscovery: true`
to publish its discovery metadata.

Hub-directed self-updates also require an exact `operator-update` approval in
the administrator-owned `hanko-image-policy` ConfigMap and a verified image
signature. Configure `imageVerification.policyConfigMap` and exact verifier
egress destinations. Without an approval, the Deployment stays unchanged.
Remote decommission commands must carry a valid, unexpired time window.
See [remote command authorization](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#hub-remote-commands).

Database snapshot Jobs also require `imageVerification.policyConfigMap`, with an
exact `database-backup` digest/source/publisher approval. Set snapshot
`spec.backupImage` and a dedicated `spec.backupSecretRef`; there is no default
PostgreSQL image or implicit reuse of the Keycloak database credential. Only
selected PostgreSQL connection keys enter the Job. Review its separate image
security evidence and configure workload-specific database networking/storage;
the operator image scan does not cover this executable. See the
[database snapshot contract](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#database-snapshot-jobs).

`leaderElect: true` remains the default. An explicit `false` now reaches the
manager flag (previously omission left its default enabled); use it only with
one active writer. This is not a multi-replica failover mode.

Release packaging pins the exact scanned image digest and includes curated notes,
checksums and verified delivery evidence. Publication requires a GitHub-verified
source commit and a GitHub-verified signed annotated SemVer tag bound to that
exact commit on protected main. The named Attest verification-key link
is for receipt verification, not Helm OpenPGP `.prov` signing. Artifact Hub Verified
Publisher identifies repository ownership, not an image-security endorsement.
The [nonpublishing rehearsal](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#release-rehearsal-and-publication)
uses fixture trust and cannot qualify production publication credentials.

`keycloak.url` defaults to `https://keycloak.auth.svc:8443`; replace it with the
actual administrative endpoint and its certificate hostname. An enabled
Keycloak requires a nonempty, valid URL. Helm rejects userinfo, queries,
fragments, invalid ports, encoded/ambiguous context paths and dot segments.
Plain context paths such as `/auth` are supported. The in-cluster default
`networkPolicy.keycloakPorts` is `[8443]`; configure actual Service/target ports.

HTTPS with a publicly trusted certificate works without `keycloak.caSecret`.
A private CA uses the existing dedicated `caSecret`/`caKey` mount. Both paths
verify certificate trust and hostname, using TLS >=1.2 in standard and TLS 1.3
in enterprise. No certificate-verification bypass is available.

**Migration:** an existing `http://` value fails rendering until the administrator
sets `keycloak.allowInsecureHTTP: true` explicitly. Prefer switching that endpoint
to verified HTTPS. The flag defaults to `false`, applies to this operator's
Keycloak connections (including instance/tenant credentials and rotation), and
is forbidden as an `env` override. HTTP with a CA Secret is rejected; enterprise
rejects HTTP regardless of the flag. Plaintext HTTP exposes administrative
credentials, bearer tokens and Admin API traffic to parties on the network path,
and provides no server authentication. NetworkPolicy does not encrypt traffic.
See the [transport migration guide](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#keycloak-administrative-transport).

For `HankoKeycloakInstance` in managed mode, `spec.managed.tlsSecretRef` supplies
a same-namespace `kubernetes.io/tls` serving Secret. The Deployment, Service and
ingress policy use HTTPS/8443; `spec.tlsCARef` is separate client-side CA trust.
Supply an optimized image built for its database with health enabled. The health
listener stays on HTTP/9000 with no Service or pod ingress; it carries no IAM
credentials. Managed HTTP requires both `spec.managed.allowInsecureHTTP: true`
and `keycloak.allowInsecureHTTP: true` in standard profile, without a serving TLS
Secret. Enterprise refuses it. See the [managed contract](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#managed-keycloak-transport).

Configure an exact image digest, existing Keycloak Secret, dedicated watch
namespace, authority realm and protected clients. Supply your Kubernetes API
Service/endpoint addresses to the NetworkPolicy; API egress is closed by
default. Review image policy ownership before enabling workload execution.

## Metrics and Prometheus

`metrics.enabled` is the global switch, defaulting to `false`. Disabled metrics
set the manager bind address to `0` and render no metrics port, Service,
ServiceMonitor, Prometheus annotations or metrics ingress. Health probes keep
their separate port 8081. The standalone binary also defaults to disabled metrics;
an explicit `--metrics-bind-address=:8080` enables it outside Helm.
The global switch overrides a retained `serviceMonitor.enabled: true`, so disabling
metrics requires no secondary toggle and no Prometheus API.

Enabled metrics bind port 8080 and expose the existing release-owned ClusterIP
Service. With `metrics.serviceMonitor.enabled: false`, pod annotations advertise
`/metrics` on 8080; your Prometheus configuration must implement annotation
discovery. With it set to `true`, the chart instead creates a ServiceMonitor and
omits the pod scrape annotations to avoid duplicate discovery. This requires the
installed Prometheus Operator API; offline rendering needs
`--api-versions monitoring.coreos.com/v1/ServiceMonitor`.

When `networkPolicy.enabled` is true, **every enabled metrics configuration**
requires both `metrics.networkPolicy.namespaceSelector` and `podSelector`, even
without a ServiceMonitor. Only nonempty exact `matchLabels` are accepted.
The namespace selector must include `kubernetes.io/metadata.name` for one actual
Prometheus namespace; expressions, empty identities and IP grants are rejected.
One ingress peer combines both selectors with AND and permits only TCP/8080.
Other ingress remains denied. Example (replace labels with those on your pods):

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

Ensure Prometheus selects ServiceMonitors in the operator's namespace and their
metadata labels. `serviceMonitor.labels` can match its discovery filter (for
example `release`), but cannot override chart identity labels. The monitor selects
only this release's Service in its own namespace. Creating it does not install
Prometheus or change Prometheus's discovery or egress configuration.

Metrics are unauthenticated HTTP and may disclose operational details. NetworkPolicy
limits network reachability; it does not provide encryption or application
authentication. CNI enforcement and other additive policies require installation
verification. The optional Cilium egress policy does not add metrics ingress.
Disabling baseline NetworkPolicy in a standard installation explicitly relinquishes
this chart's ingress restriction; enterprise still requires it.

**Migration:** the previous `metrics.enabled` controlled only ServiceMonitor
creation. To retain that discovery, set both `metrics.enabled: true` and
`metrics.serviceMonitor.enabled: true`, configure the explicit Prometheus identity
and discovery labels. The old flag alone fails rendering with default networking.
Existing names and port 8080 are retained. Keeping the default `false` now removes
the previously always-on listener, Service and annotations. Rolling back to an
older chart restores its previous exposure and flag meaning; review the render.

See the [verification steps and network limitations](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#metrics-and-prometheus).

For Keycloak in another namespace, set `networkPolicy.keycloakNamespace`,
`keycloakSelector` and `keycloakPorts` to its actual pod labels and Service/target
ports. For an external endpoint, set `keycloakSelector: null`, exact
`keycloakExternalCIDRs` and `keycloakExternalPorts`. Use `keycloak.caSecret` and
`caKey` for an existing private HTTPS CA Secret. Per-instance clients also
support `spec.tlsCARef` independently of this default connection.

`networkPolicy.kubernetesAPIEndpointPorts` supports managed API endpoints on
443 as well as 6443. DNS is limited to `dnsNamespace` and `dnsSelector`; optional
`dnsCIDRs` allow exact node-local cache addresses with a compatible CNI.

`networkPolicy.cilium.enabled` adds a namespaced CiliumNetworkPolicy for the
operator pods. `cilium.kubernetesAPI` uses the `kube-apiserver` entity; optional
`cilium.fqdnEgress` entries require an exact lowercase `matchName` and explicit
TCP `ports`. The cluster must already expose `cilium.io/v2/CiliumNetworkPolicy`
and support those features. DNS-name egress requires a working Cilium DNS proxy
and pod-selected DNS, and rejects the broad `externalEmailEgress` option and
node-local DNS CIDRs. Offline Helm rendering needs
`--api-versions cilium.io/v2/CiliumNetworkPolicy`.

Kubernetes and Cilium allow policies are additive: review any other policies
selecting these pods. DNS rules follow resolved IPs, not HTTP hostnames or TLS
identities. Managed Cilium implementations vary, particularly GKE and AKS;
their branding alone does not establish support for this optional profile.
The baseline Kubernetes policy remains available without Cilium. Neither
profile grants BPF capabilities, host networking or CNI administration.

`profile: enterprise` requires `hub.enabled`, `continuum.enabled`, baseline
NetworkPolicy and an immutable `image.digest`. Set `hub.endpoint` to the exact
`https://<continuum.hubHostname>:<continuum.hubPort>` origin and supply the
private `continuum.hubAddress`. The operator dials that IP directly, verifies
the Hub TLS name with TLS 1.3, refuses redirects and ignores environment
proxies for synchronization. CRDs cannot switch it to another Hub endpoint or
to direct transport; identified, unexpired Hub credentials are required.
Keycloak clients (including instance, import and dedicated tenant clients),
organization projection and supervision/audit clients require verified TLS 1.3
and reject HTTP, origin changes, redirects and environment proxies. Configure
their actual TLS Service/target ports and certificate trust; the optional API
integrations expose `organizationProjection.apiPorts` and `supervision.apiPorts`.

For initial enterprise enrollment, set a single-use `hub.enrollToken`, an
explicit HTTPS `hub.enrollmentEndpoint` and exact `continuum.bootstrap.cidrs`.
After enrollment, keep `hub.tenantID` and the credential Secret, remove the
bootstrap token and clear its CIDRs. Direct `hub.externalCIDRs` are rejected.
Return to direct transport requires an explicit profile/configuration change.

Continuum remains a separately installed node DaemonSet. This profile does not
install it, qualify network enforcement, enable mTLS on every integration, or
promote `meshPolicyAudit` to workload enforcement. Admission of Attest-approved
operator images remains a separate installation control; a digest pins content
and does not establish publisher provenance. Standard installations remain
available with `profile: standard` and independently selected integrations.

Helm does not upgrade CRDs under `crds/`. Review and apply the canonical
schemas separately before upgrading. No cluster change is authorized by a
published chart alone.

Read the [source README](https://github.com/Alien6-Studio/hankoshell-operator#deployment)
and [secure deployment guide](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md)
with its Hub bundle trust model, plus the [security policy](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/SECURITY.md).
This chart includes the Apache-2.0 license and project notice.
