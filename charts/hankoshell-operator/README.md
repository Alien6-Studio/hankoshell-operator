# hankoShell Operator chart

Helm chart for declarative Keycloak IAM configuration with hankoShell Operator.
`reconciliation.maxConcurrent` defaults to 1 and accepts integers 1–8 for the four
reviewed IAM controllers. See the [concurrency review and scale qualification](../../docs/scale-and-soak.md)
before increasing it; this setting is not a measured capacity recommendation.
Target 0.1.0 is in initial development; current chart/app metadata is the
prerelease `0.1.0-dev.0`. No public release has been published yet.
The source includes the [OIDC/SAML application contract](../../docs/architecture/application-identity.md),
including explicit migration approval for existing unmarked clients and
[UID-bound runtime bindings](../../docs/architecture/application-identity.md#runtime-bindings).
Public chart/image artifacts remain pending. Runtime target namespaces need
explicit resource-name-limited Roles; the chart grants no broad target write
permission. Provision the targets and their current application/ServiceAccount UID
consent before requesting delivery.
The chart installs 17 experimental `hanko.sh/v1alpha1` CRDs. These APIs may change
between minor versions. All controllers are registered; integration flags
configure their connections to optional services.

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

Before changing storage or applying CRDs to an existing installation, follow the
[storage migration runbook](../../docs/storage-migration.md). Helm upgrades do not
update crds/; the live stored-version guard refuses an unreadable rollback.

See the [support and field-group inventory](../../docs/api-support.md) and
[API migration policy](../../docs/api-migration-policy.md) before upgrading CRDs.

The generated support table below defines the exact Kubernetes qualification window on Linux nodes. CI uses
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
For adopted HankoRole Manage, target-only `manage-realm` also permits realm
security changes/deletion, even though the controller never performs them. Use a
dedicated role writer where possible; see the
[credential blast-radius contract](../../docs/keycloak-permissions.md#dedicated-hankorole-writer-target-realm-exception).

Organization principals require explicitly
provisioned target `view-users` in addition to `manage-clients`; that read role
also exposes realm users. No chart flag grants this authority. See the
[organization-grant contract](../../docs/keycloak-permissions.md#organization-principals-010)
for direct/descendant semantics, ownership, bounds and the reconciliation window.

Real HTTPS Admin API v1 qualification covers only the exact Keycloak versions in the generated support table below.
Other patches and major lines are unqualified. Hub/Continuum integrations are
optional; standalone Keycloak reconciliation does not depend on them. See the
[qualification limits](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md#keycloak-compatibility)
and project website [hanko.sh](https://hanko.sh).

Signed fleet plans are opt-in: set `hub.enabled: true` and
`fleetPlanVerification.trustConfigMap: hanko-fleet-plan-trust` only after a local
policy administrator provisions and protects that ConfigMap and Hub supports the
new signed media type. The chart does not create publisher trust or admission
authority. See the [transition and rollback guide](../../docs/secure-deployment.md#signed-fleet-plan-transition).
An accepted signed checkpoint forbids returning that tenant to legacy HMAC.

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

Metrics are off by default. When enabled, TLS 1.3, trusted client certificates
and exact authorized SPIFFE URI SANs are required. Server certificates and client
CA trust come from pre-existing namespace-local Secrets. The ServiceMonitor uses
HTTPS with server CA/DNS verification and client certificate authentication.
No pod scrape annotations or anonymous/plaintext mode are provided. Exact
Prometheus namespace AND pod labels still constrain ingress on TCP/8080.
The Pod readiness probe excludes the leader check so healthy standbys remain Ready;
the full `/readyz` endpoint reports reconciliation readiness.

Operational procedures: [runbooks](../../docs/operations-runbooks.md), [secure observability](../../docs/operational-observability.md) and the [machine contract](../../docs/operational-contract.json).

See the observability guide for complete values, trust rotation, migration,
label bounds, alerts, dashboard and qualification limits.

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

## Organization projection

`organizationProjection.enabled=false` is the standalone default. The chart
always passes the explicit boolean to the process, mounts no API token/URL and
opens no projection egress when disabled. Organizations can be Ready without a
PositionID. Enabled projection requires a URL, token Secret/key and exact network
destination/ports; enterprise keeps verified HTTPS mandatory. Configured API
failures preserve provider Synced=True while Phase is Error (or Pending for a
parent projection dependency). See [configuration, status and migration](../../docs/secure-deployment.md#organization-provider-readiness-and-optional-projection),
including residual position cleanup after disabling projection.

ResourceServer status can explain bounded structural organization/role grants
without exposing users. Enable the externally provisioned optional read profile
for role provenance; it is independent of authorization synchronization. See
[structural provenance](../../docs/architecture/organizational-authorization.md#bounded-effective-explanation)
and [read permissions](../../docs/keycloak-permissions.md#optional-structural-role-provenance-reads).

Existing-Keycloak inventory uses HankoImport.sourceRef and the referenced external
instance's dedicated read-only AdminRef/TLSCARef. The shared writer pool is not an
inventory fallback. Credential/CA Secrets require named GET, never list/watch.
Review the [inventory permissions](../../docs/keycloak-permissions.md#dedicated-inventory-identity)
and [bounded evidence contract](../../docs/architecture/existing-keycloak-adoption.md#implemented-discovery-and-diff-47).
Done and complete coverage are separate; candidate status is not adoption approval.

For the reviewed source ownership flow, follow the
[reviewed leaf adoption workflow](../../docs/architecture/existing-keycloak-adoption.md#implemented-reviewed-leaf-acquisition-48)
and [service-account upgrade guidance](../../docs/secure-deployment.md#reviewed-existing-client-ownership).
Approval is target-local Kubernetes metadata, not a chart flag. Existing unmarked
M2M clients require reviewed acquisition. Leaf and
[aggregate checkpoints](../../docs/architecture/existing-keycloak-adoption.md#implemented-aggregate-acquisition-and-native-preservation-49)
remain Observe until an administrator explicitly requests Manage and removes the
imported latch. Exact current ownership and qualified native preservation are
required; foreign dependencies hold cleanup. Chart/app source metadata is 0.1.0-dev.0;
source freeze requires exact-main qualification. Production publication remains
pending in #21.

## Initial public contract selection

See the [complete candidate review](../../docs/public-contract-selection.md).

<!-- public-selection:start -->
Initial 0.1.0 selection: 3 public resource candidates; qualification and first publication remain pending. Current development APIs remain experimental.

| Resource | Selected scope | Public spec groups |
| --- | --- | --- |
| `HankoApplication` | public | `clientID`, `mode`, `postLogoutRedirectURIs`, `protocol`, `realmRef`, `realmRoleScopes`, `redirectURIs`, `roles`, `saml`, `type` |
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

Native SAML remains an explicit Keycloak extension. Delegation, organization principals,
connected integrations and every other deferred field retain their named limitations in
the complete selection; no planned capability is removed.
<!-- public-selection:end -->

## Experimental authentik registration

`experimental.authentik.enabled` defaults to false. Enabling it requires explicit
`experimental.authentik.connectionNames` and explicit
`experimental.authentik.egress.namespace`, `.selector` and `.port`, with the baseline
NetworkPolicy enabled. The chart adds only that namespace/pod/TCP grant and controls
`HANKO_EXPERIMENTAL_AUTHENTIK_ENABLED` and the connection-name allow-list. A
fail-closed admission policy protects the selected ConfigMaps against ordinary
writers. Only `system:masters` and optional `experimental.authentik.adminGroups`
may provision/update them. Review existing ConfigMaps before enabling their names.
No provider credential or CA is generated.

An application selects an administrator-owned, same-namespace typed connection
ConfigMap using `hanko.sh/provider-connection`. See the
[exact version, semantics, permissions and recovery boundary](../../docs/architecture/second-provider.md).
The adapter currently qualifies registration of a bounded OIDC SPA/web subset on
a real server. Its installed matrix and confidential credential delivery remain
unqualified. Disabling it retains existing cleanup finalizers and refuses writes.

The [1.0 graduation criteria and per-resource records](../../docs/stable-graduation.md)
and [second-provider contract review](../../docs/stable-provider-review.md) remain
unratified development inputs. Lifecycle APIs are excluded from the stable 1.0
contract and disabled by default; see [ADR-050](../../docs/architecture/decisions/ADR-050-experimental-lifecycle-authority.md).

Qualification window: [support policy](../../docs/support-window.md), [compatibility proposal](../../docs/compatibility-policy.md).

<!-- support-window:start -->
| Component | Exact qualification versions | Default |
| --- | --- | --- |
| kubernetes | `1.35.0`, `1.36.2`, `1.37.0` | `1.37.0` |
| keycloak | `26.7.5`, `26.8.0` | `26.8.0` |
<!-- support-window:end -->
