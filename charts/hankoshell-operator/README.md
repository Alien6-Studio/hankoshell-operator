# hankoShell Operator chart

Helm chart for the hankoShell Kubernetes operator. The `0.x` series is in initial
development; public APIs may change between minor versions. It retains all 16
`hanko.sh/v1alpha1` CRDs and registers all existing controllers; optional
integration flags do not define an IAM-only controller profile.

Kubernetes **1.35–1.37** and Linux nodes are the qualification window. CI uses
real API-server/etcd fixtures to check CRDs, server-side apply, RBAC and Restricted
admission on each minor. Future minors and upstream prereleases are rejected
until qualified. Install the latest provider security patch; fixed CI fixtures
do not certify nodes, CNI/CSI or cloud-provider behavior.

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

Configure an exact image digest, existing Keycloak Secret, dedicated watch
namespace, authority realm and protected clients. Supply your Kubernetes API
Service/endpoint addresses to the NetworkPolicy; API egress is closed by
default. Review image policy ownership before enabling workload execution.
The default `nameOverride: hanko-operator` preserves existing Kubernetes
names/selectors through the hankoShell branding migration.

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
