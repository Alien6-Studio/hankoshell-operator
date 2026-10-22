# Secure deployment and trust model

Use this guide with the [chart configuration](../charts/hankoshell-operator/README.md),
[values](../charts/hankoshell-operator/values.yaml) and [security policy](../SECURITY.md).
An installation needs reviewed credentials, provider ownership and network
destinations before the operator can reconcile resources.

## Reviewed existing-client ownership

Use the [explicit adoption workflow](architecture/existing-keycloak-adoption.md#implemented-reviewed-leaf-acquisition-48)
for existing applications, roles, service accounts and
[qualified aggregates](architecture/existing-keycloak-adoption.md#implemented-aggregate-acquisition-and-native-preservation-49). Keep the target Observe,
review its live candidate and approve the exact source/contract/hash. Ownership
acquisition writes only owner+receipt, verifies unchanged UUID/configuration and
stops. Source credentials are independent read-only inventory credentials; the
normal writer must identify the same endpoint and realm UUID. No client-secret
endpoint is called by adoption. A provider receipt is a trusted-provider checkpoint,
not a signature or semantic reconciliation/deletion permission.

**Service-account upgrade:** existing unmarked legacy M2M clients cannot receive
writes, recovered/rotated credentials or deletion merely because clientID, status,
Secret or finalizer matches. Set Observe and obtain reviewed acquisition for a
qualified leaf. Opaque/unqualified native state remains refused; do not
forge owner attributes. New service accounts get a kind/UID envelope before secret
retrieval. Imported labels remain Observe latches and are never removed automatically.
After acquisition, explicitly set Manage and remove the imported latch to request
semantic reconciliation. The operator rechecks exact current ownership and the
closed preservation schema before writes/credentials. Source/approval metadata
may then be removed. Deleting an Observe declaration preserves Keycloak state.
Manage deletion holds `CleanupConflict` when foreign/native dependencies or
current ownership prevent safe cleanup. Adopted realm-role cleanup remains held
because absence of every foreign reference is not bounded/qualified.
Lost HTTP/status acknowledgements
recover from the exact provider receipt without repeating the ownership PUT.

## HankoRole writer: complete target-realm credential blast radius

HankoRole Manage is enabled under the explicit
[§117 exception](architecture/existing-keycloak-adoption.md#117--provider-authority-and-hankorole-exception).
Realm-role create/update/delete/composition requires the qualified Keycloak
`manage-realm` built-in role on the target realm. That credential can also mutate
configuration/security and **delete the entire same target realm**. Keycloak's
qualified built-in permission cannot express role-definition-only management.

Recommend a dedicated role-writer identity per target realm wherever the deployment
architecture permits it. Keep Full Scope Allowed disabled and permit exactly the
reviewed role scopes for that target only; never add `realm-admin`, master
`manage-realm`, master/global `admin`, `create-realm` or unrelated-realm grants. Authentication in master
is distinct from authority over master. A shared process's credential has the
union of its granted capabilities; separate identities must also be isolated from
processes that should not hold them. Dedicated identity compromise still exposes
the **complete target realm**, not just the declared or owned roles.

Ownership checks authorize controller actions; Kubernetes objects do not
cryptographically restrict the provider credential. An imported/external HankoRealm
remains Observe-only, without realm ownership markers or lifecycle finalizers.
Normal HankoRole reconciliation uses only qualified role definition/composite
operations and necessary read-only identity checks: no realm-level PUT/DELETE,
security reconciliation or realm deletion. Real-Keycloak credential probes that
change security/delete a disposable target realm document permission breadth,
not controller behavior. Application, ServiceAccount, ResourceServer and Organization
writers retain strict provider-enforced realm deletion/security mutation denial.

Reviewed candidates, exact provider UUID and target UID, verified receipts and
native preservation still precede an explicit Observe → Manage transition.
Conservative adopted-role cleanup refusal remains necessary when complete absence
of foreign references cannot be proven. For deployment permissions and qualification
profiles, see [the Keycloak permission contract](keycloak-permissions.md#dedicated-hankorole-writer-target-realm-exception).

## Trust boundaries

For independent Kubernetes trust, provision three distinct
[Trust profiles](keycloak-permissions.md#workload-identity-qualification):
trust-writer (`manage-identity-providers`, `view-realm`), trust-observer
(`view-identity-providers`, `view-realm`) and dependent-client-reader
(`view-clients` only on the target realm). Keep Full Scope Allowed off and exact
role mappings/scopes. The writer receives no view-clients concession. The reader
controller permits only bounded client metadata GET; secret/credential and write
routes are refused before dispatch. **26.7.5 still permits this credential to
read native client secrets.** A stolen reader credential can expose target-realm
secrets; route restrictions do not narrow native token powers. 26.8.0 has the
stricter native client-secret denial. Distinct identities in the current single
manager process/pod are not process isolation: compromise gives the practical
union of every loaded credential. The writer also retains realm-wide IdP powers.

Use independently reviewed current kube-system UID and the single public API CA
DER hash in the trust spec. Ensure approved public HTTPS issuer/JWKS discovery is
reachable without credentials; the controller never configures public access or
repairs client-authentication flows. See the
[implemented trust ownership and recovery contract](architecture/workload-identity.md#implemented-kubernetes-workload-trust-ownership).
Trust Ready means configuration only, with no workload binding, token issuance,
federated HankoServiceAccount activation or mesh authority.

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

### Exact Secret and Deployment write authority

An installation administrator approves each output before its CR is submitted:

```yaml
sensitiveWrites:
  secrets: [hanko-app-orders, hanko-sa-billing-worker]
  deployments: [reviewed-keycloak]
  projections:
    - namespace: orders
      secrets: [orders-credentials]
      create: false
```

The empty defaults grant no Secret or provider Deployment creation. Updates and
patches use exact `resourceNames`; mandatory `ValidatingAdmissionPolicy` bindings
also deny other names/namespaces on CREATE, UPDATE and DELETE. Kubernetes
[RBAC cannot restrict CREATE by resource name](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources).
The policies fail closed and cannot be disabled through chart values. The
operator cannot change them. Labels, owner references, CRs and provider journals
do not add targets to this administrator list.

Ordinary client IDs keep `hanko-app-<clientID>` or `hanko-sa-<clientID>`. When that
complete string is not a valid Kubernetes DNS subdomain of at most 253 bytes,
use `hanko-app.<sha256>` or `hanko-sa.<sha256>`: the full lowercase SHA-256 of the
exact UTF-8 client ID, without normalization or a trailing newline. These hashed
names occupy a separate namespace from all previously valid names; valid existing
Secrets are preserved. The [independent vectors](../internal/credentialname/testdata/names.json)
include URNs, Unicode and long IDs. SAML and public SPA clients do not need
credential outputs. Explicit rotation targets must be approved separately;
referencing an input Secret does not authorize writing it. Enabling Hub approves
only its configured token Secret automatically.

Cross-namespace projections grant named get/patch only. `create: true` separately
authorizes creating those exact outputs. Existing application/ServiceAccount UID
consent and controller ownership checks remain necessary. Workload SA/ConfigMap
metadata delivery uses the separate `workloadBinding.grants` configuration.
Credential writes accept only Opaque Secrets and reject ServiceAccount-token
annotations/types. Transport teardown deletes only configured exact Secrets or
Helm history matching the configured release namespace, name, type and labels.

Deployment writes require namespace Pod Security labels `enforce=restricted`
and `enforce-version=latest` or the installed Kubernetes minor (omitting the
version also selects the current version). The operator cannot change those
namespace labels. Existing Deployment ServiceAccount bindings are immutable to
the operator; newly managed providers use default/no account and explicitly
disable automount and projected ServiceAccount tokens. RBAC adoption may change
owner references for decommissioning, while rules, subjects, role references,
aggregation rules/labels, annotations and finalizers remain unchanged.
Theme/snapshot Jobs keep dynamic checkpoint names, but their mandatory execution
policy requires the release namespace, current Restricted admission, default/no
ServiceAccount and no automatic/projected API token. A Job cannot serve as a
route around the exact Secret/Deployment targets.

Before upgrading an existing development installation, inventory all output
names, managed Deployments, explicit credential rotation and runtime projections.
Provision namespace admission and apply the reviewed values/policies before
resuming reconciliation. A missing grant fails the write and leaves the CR
unready; do not remove the admission policy to repair configuration. Prune grants
only after their workloads and unfinished transactions have been reviewed.
Existing Secret data and provider ownership checkpoints require no renaming.
Rolling back to a chart with broad writes removes these protections; suspend
writers and retain independently administered admission if rollback is necessary.

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

The default bundle wire contract remains HMAC. An explicit signed fleet
transition adds independent publisher verification with the protocol below;
the Hub must implement that protocol before it can be enabled.

#### Signed fleet plan transition

The [Fleet contract](architecture/fleet-reconciliation.md) and
[ADR-010](architecture/decisions/ADR-010-locally-approved-fleet-plans.md) define
the exact Ed25519 signing input, closed JSON, local key scopes, expiry and
sequence rules. In a reviewed deployment:

1. Provision publisher public keys and exact tenant/cluster/namespace/source
   tuples in `trust.json` of the same-namespace `hanko-fleet-plan-trust` ConfigMap.
   Obtain keys through the independent local approval process. The private signer
   belongs outside the cluster; never put it or Hub credentials in that ConfigMap.
2. Independently install [the trust admission policy](../config/security/fleet-plan-trust-admission.yaml)
   before enabling verification. Its default target is namespace `auth` and that
   exact ConfigMap name. Customize both if the deployment uses another location.
   Only policy administrators with the separate `update` authorization on
   `kube-system/hanko-fleet-trust-authority` may change this root. Do not grant
   that authorization or policy/binding administration to the operator or CR
   authors. The policy does not create or store a credential in that name.
3. Require a compatible HTTPS Hub route serving
   `application/vnd.hanko.fleet-plan+json`, an enrolled cluster identity and current
   locally approved issuer keys. Enable `hub.enabled` and set
   `fleetPlanVerification.trustConfigMap` to the protected name. The process uses
   `HANKO_FLEET_TRUST_CONFIGMAP`; no tenant spec or remote plan selects it.
4. Review `status.fleetPlan` and the Synced condition. Acceptance persists the
   monotonic identity before child writes; applied identity describes Kubernetes
   delivery, not provider convergence. Rotation needs a locally approved fresh
   key ID and a higher-sequence plan. Revocation stops subsequent verification.

Once a signed checkpoint exists, removing the setting, deleting trust or serving
an old HMAC response fails closed. For binary rollback, suspend the operator and
retain the newer CRD/status, then review actual child/provider state. An older
binary cannot enforce this ratchet. Do not clear a checkpoint or prune/downgrade
the CRD to bypass it. A previous identity is evidence for future reviewed rollback,
not rollback execution. Capability-aware rollout and local stop controls follow
the [conservative Fleet profile](architecture/fleet-reconciliation.md#capability-aware-delivery-and-local-stop-controls):
existing realms, explicit local realm binding, qualified versions and effective
native roles are required. Use protected `rollout.json` overrides to pause/refuse
new delivery; partial success stays degraded with bounded findings. Disconnected
provider expiry and installed fleet qualification remain #79/#80. Current child reconcilers can
continue acting on previously delivered declarations after a plan expires.

#### Shared bundle object ownership

Bundle application preflights object identity, metadata and current tenant labels
before any resource write. A declared foreign namespace or tenant is refused,
as is an existing object without the exact local `hanko.sh/tenant` label.
`BundleTenantConflict` reports these collisions. Bundle metadata permits only
name, namespace, ordinary labels and annotations; server metadata, owner references,
finalizers, status and reserved `hanko.sh/`, `hanko.io/` or `mesh.hanko.io/` metadata
(except the exact tenant label) cannot be supplied by Hub. This prevents a bundle
from injecting local adoption approvals or import/ownership markers.

New targets use create-only writes. Existing targets use server-side apply with
the observed UID/resource version and without forced ownership. Concurrent
creation, transfer, replacement or edits are refused with `BundleObjectConflict`.
The dedicated `hanko-hub-bundle` field manager preserves local lifecycle and
approval metadata, including fields owned by the previous `hanko-operator`
manager. The create-to-apply transition conditionally converts only the new
manager's own creation entry; other managers' fields are retained, and a lost
acknowledgement resumes from the stored entry. A spec field still owned by that
legacy manager or a local administrator can block a changed bundle: a local
administrator must review and explicitly resolve that field ownership conflict. The operator never force-transfers it.

These checks are exercised against HTTPS Hub fixtures and all supported Kubernetes
API versions, including lost creation acknowledgements. They do not make a bundle
transactional: API admission or concurrent conflicts during later writes can leave
earlier resources applied. A retry rechecks current ownership; no rollback or
successful bundle version is recorded for a failed apply. Opt-in signed Fleet
plans additionally enforce the publisher, replay and rollout controls above.
Disconnected provider expiry, controlled rollback and installed Fleet
qualification remain #79/#80.

Tenant Keycloak routing is registered before Hub enrollment, credential rotation
or bundle requests. An unavailable Hub therefore does not prevent reconstruction
of a dedicated connection after an operator restart. Dedicated credentials are
read as one current Secret; invalid credentials or a deleted tenant remove its
registration. Resources carrying `hanko.sh/tenant` never implicitly use the
installation's default client. Until their tenant is registered, the pooled IAM
controllers report `TenantClientUnavailable`, defer provider reads/writes and
retain cleanup finalizers. Realm isolation explicitly registers the shared client;
unlabelled resources continue to use the installation default. Secretless workload
authentication and imports retain their separate explicit instance references.

This routing boundary is tested with Kubernetes API servers and real HTTPS
Keycloak. It does not establish a last-verified signed plan, disconnected validity
window, replay protection or rollback authority; that qualification remains open
in [issue #79](https://github.com/Alien6-Studio/hankoshell-operator/issues/79) and
its prerequisite plan-protocol issues.

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
The Hub reference version must match the reviewed SemVer release, such as the future `1.0.0`. This example is unavailable during development.

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
    "release_version": "1.0.0",
    "certificate_identity": "https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/v1.0.0",
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

For a private registry signature intentionally absent from a public transparency
log, an administrator can add `"registry_only": true` to that exact keyed approval.
The pinned public key, digest, source revision and revocation checks remain required.
The default requires transparency verification; keyless approvals cannot opt out.

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

The exact current Keycloak qualification versions are listed in the generated support window below
using the HTTPS Admin API v1 and service-account `client_credentials` flow.
The official images are pinned by immutable multi-architecture index digests
in the [qualification fixture](../internal/controller/keycloak_fixture_test.go).
Both versions run in required PR/release CI and weekly CI; the aggregate required
check fails on either matrix failure or startup failure. Qualification is a
compatibility contract, not a recommendation to retain a vulnerable patch.

The Keycloak job runs three independent, serial shards per version: `core`,
`adoption` and `protocols`. The runner compares the compiled tagged and ordinary
test inventories with [the reviewed partition](../tools/qualification/config/keycloak-shards.json),
rejecting missing, duplicate or obsolete assignments. Ordinary controller tests
remain in `core`, so the partition retains the previous tagged suite in full.
Each shard has a ten-minute test deadline and a fifteen-minute job deadline.
Run one locally with `make keycloak-integration-test KEYCLOAK_VERSION=26.7.5
KEYCLOAK_SHARD=adoption`; omitting the shard still runs the full suite.

`make test`, `make integration-test` and `make keycloak-integration-test` use
the pinned gotestsum version from `versions.json` and write JUnit, outcome JSON
and a Markdown summary under `.tools/runs/tests/` (`TEST_REPORT_DIR` overrides
the directory). CI uploads these on success or failure and lists failed tests
in the job summary. Reports do not trigger retries, skips or weaker assertions.
The outcome JSON contains names, status and timing, without test output payloads.

The 2026-10-11 application flow and 2026-10-12 adoption failures exhausted the
fixture's five-second bootstrap HTTP deadline on client-creation POSTs. Fixture
HTTP calls now have a bounded fifteen-second budget, with no retry of ambiguous
writes; production client deadlines are unchanged. Failures preserve the last
64 fixture HTTP methods/routes/statuses/timings and redacted container logs;
headers, query values and bodies are excluded from the HTTP trace. Shard timings
on GitHub runners and twenty consecutive runs of both historically failing
tests are recorded through the [concurrency and stability qualification](qualification.md).
Its independent series stops on the first failure and retains every JUnit; it
does not replace the required twenty-run `main` history window.

The weekly `Go test history` workflow reads the last twenty completed `main` CI
runs and compares outcomes only for the same commit, test and suite/version.
Earlier attempts remain visible when a job is manually rerun; a successful retry
cannot erase a recorded failure. Reports from modified local checkouts are marked
as such and are refused by the history collector.
Its artifact and job summary distinguish mixed pass/fail results from missing or
expired reports. It has read-only permissions and does not publish issue comments;
tracking-issue automation is handled separately in #111. Historical runs without
JUnit outcome artifacts cannot count toward a twenty-run stability qualification.

| Version | Current qualification |
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

Canonical application credential Secrets must have a controller owner reference
matching the current HankoApplication name, UID, kind and API version. An existing
foreign or ownerless Secret at the canonical name is a conflict, never implicitly
adopted. Resolve such a collision through its owner before retrying. The controller
compares an owned credential with the current provider value without rotating it,
and repairs drift before reporting credential readiness. This adds a bounded
credential read during each managed confidential-application reconciliation.
Observe, public-client and SAML paths do not gain credential reads.

Canonical and legacy projected Secret writes use resource-version preconditions
and live identity/value read-back. Legacy projections retain their documented
initial authorization compatibility; replacement, deletion or revoked consent
cannot be acknowledged as current delivery. A conflict requires a fresh reconcile.

All Hub clients refuse redirects, including public enrollment and legacy HMAC
routes. Configure the final endpoint directly instead of relying on a redirect.
Hub error responses expose only locally authored operation/status diagnostics,
never their remote response bodies. Legacy bundles share the signed Fleet
aggregate maximum of 200 objects across all kinds; larger bundles must be split
at the publisher before retrying. Byte limits remain independently enforced.
These transport checks do not independently authorize the initially configured
Hub origin or bind arbitrary provider Secret references to a local approval.

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

Organization principals require the optional
target `manage-clients` + `view-users` profile. `view-users` also permits reading
target-realm users; it is not group-only authority or part of the common profile.
Fresh strict group ownership/hierarchy reads precede grant execution. Missing
authority refuses authorization writes; an old applied UUID snapshot can remain
active until successful reconciliation or direct provider revocation. See
[organization permissions and consistency](keycloak-permissions.md#organization-principals).

Unmanaged clients, roles and brokers survive child reconciliation/deletion.
Deleting a managed realm is an explicit destructive ownership boundary: once
managed applications/service accounts/issuers are gone, Keycloak deletes the
realm and **all contents**, including objects added outside the operator. Separate
unrelated realms and master configuration survive this path. Keep backups and
review ownership before deletion; neither reverting the operator nor the chart
restores deleted provider state or previously rotated credentials.

The suite uses Keycloak's disposable `dev-file` database in production server
mode and a fake Kubernetes client. It does not qualify PostgreSQL, clustering,
MFA challenges, actual upstream federation, Admin API v2, custom
providers/themes, arbitrary application authorization enforcement, managed/adopted instance
rollouts, backups/restores, or cloud/CNI/storage behavior. Those surfaces require
installation acceptance tests. No runtime version rejection is added.
The organization-grant suite qualifies fresh UMA decisions for its bounded
group-policy fixtures on both versions; it does not qualify offline/RPT token
revocation, external group-population flows or application enforcement.
Currently, application discovery/metadata uses the configured
Keycloak CA transport with TLS verification and a 1 MiB response limit, without
administrative bearer credentials. The additional protocol suite qualifies OIDC
web/SPA authorization code + PKCE, M2M client credentials and signed SAML POST
responses/assertions on both Keycloak versions. Public realm frontend URL and
private administrative URL separation is tested through two TLS-verified origins.
These tests do not qualify arbitrary production SPs or MFA/federation scenarios.
See [application identity, ownership migration and protocol limits](architecture/application-identity.md).

### Application protocol ownership and migration

`spec.protocol` defaults to OIDC; existing field paths remain valid. The protocol-aware application
source supports a bounded SAML contract and never creates an OIDC Secret for a
SAML application. Client roles are shared; OIDC token/broker mappings, role scopes,
rotation and Secret projection cannot be requested for SAML. Protocol changes
require reviewed deletion/recreation, not an in-place conversion.

Legacy unmarked application clients lack UID ownership. Review the actual client UUID
and independently observed non-secret state, then explicitly approve both through
the migration annotations. A matching clientID, client Secret or status hash alone
cannot authorize adoption. Review applications before deleting them: client
cleanup also removes its roles, mappers and credentials. See the
[exact migration procedure and threat model](architecture/application-identity.md#ownership-and-legacy-client-migration).

### Kubernetes compatibility and hardening

The operator and chart keep their own development SemVer (`1.0.0`); they do not share the
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

CI starts a real API server and etcd for each fixture, installs all 17 CRDs and
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
Azure and other installations still need acceptance tests of networking,
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
[README](../README.md#install-from-source). Verify that the operator can reach its API
and provider, and that unauthorized ingress/egress is denied. Test the actual
CNI, DNS and API endpoint routing on each target cluster; Kubernetes and Cilium
allow policies are additive when other policies select the same pods.

If theme Jobs, managed provider image updates or Hub self-updates are enabled, pre-provision
the image-policy ConfigMap and install the independent
[admission policy](../config/security/operator-image-policy-admission.yaml).
It initially binds the `auth` namespace; adapt and review that binding for
another namespace. An empty image policy denies new workload image execution.

## Metrics and Prometheus

Metrics are off by default. When enabled, TLS 1.3, trusted client certificates
and exact authorized SPIFFE URI SANs are required. Server certificates and client
CA trust come from pre-existing namespace-local Secrets. The ServiceMonitor uses
HTTPS with server CA/DNS verification and client certificate authentication.
No pod scrape annotations or anonymous/plaintext mode are provided. Exact
Prometheus namespace AND pod labels still constrain ingress on TCP/8080.
The Pod readiness probe excludes the leader check so healthy standbys remain Ready;
the full `/readyz` endpoint reports reconciliation readiness.

See the [operational runbooks](operations-runbooks.md) and
[secure metrics configuration](operations-runbooks.md#secure-metrics) for Secrets,
trust rotation, label bounds, alerts and the dashboard.

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
Before creating children, the snapshot records its generation, specification/tenant
hash and source instance UID. Configuration is captured in an immutable ConfigMap;
status records its UID and content hash before submitting a database Job. Retries
reuse that stored capture without enumerating live configuration again. Each child
must retain this snapshot's owner UID and intent marker. Status also records the
Job UID; deleted or replaced checkpointed children are refused rather than recreated.
Transient errors reading the source, listing configuration or reading/creating
children, and status-write failures are retried, including lost acknowledgements.
A failed Job cannot yield a successful snapshot, even with a
contradictory completion condition. These paths are tested against the supported
Kubernetes API servers; the tests do not execute a database backup or qualify restore.

Configuration capture includes only realms, applications, service accounts and
issuers in the snapshot's namespace with the exact same `hanko.sh/tenant` label
identity. An unlabelled snapshot captures only unlabelled resources; an explicitly
empty tenant label is distinct from an absent label. The source instance must
match this scope as well. Namespace-scoped RBAC still determines who can read
the resulting ConfigMap; tenant labels are not a Kubernetes access-control boundary.
Before accepting an existing capture after interruption, the controller verifies
the tenant and namespace of every stored resource in addition to ownership and
content hashes. A legacy namespace-wide capture containing another scope fails
with `ConfigMapContractMismatch`, without rewriting the immutable capture or
starting a database Job.
The six installed workload cells also exercise this boundary with the scanned
operator image. Both deep-migration cells inject loss of an accepted capture
response, restart the manager and check exact UID/content preservation without
another create. They separately seed an owned legacy cross-tenant capture after
the authority checkpoint and require refusal without rewriting it or creating a
backup Job. This qualifies configuration-capture recovery, not database recovery
or the complete Upgrade/Clone/DBSwitch workflows.

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
For this tenant-isolation change, review existing snapshot ConfigMaps for
configuration outside their intended scope using an administrator identity.
Restrict access and retain or remove affected captures according to the local
retention policy. Create a new snapshot after correcting the scope; do not copy
foreign configuration into a replacement capture or clear a failed checkpoint.
Rolling back to the older operator reintroduces namespace-wide capture, so
suspend new snapshot operations before such a rollback.
In-flight snapshots without identity checkpoints, changed specifications or tenant
labels, and recreated source instances are refused. Inspect their children and
backup PVC before starting a new snapshot; do not clear checkpoints to force replay.
Deletion stops further reconciliation and permits child garbage collection; it
does not undo a database dump or make concurrent snapshots transactionally consistent.
Portable backup/restore, consistency and recovery across database versions or
cloud providers are not qualified. `HankoOperation.snapshotBefore` creates only
a configuration snapshot and does not establish a database rollback point.

## Lifecycle operation qualification

`HankoOperation`'s `Upgrade`, `Clone` and `DBSwitch` workflows remain experimental.
Installed qualification covers only the Clone subset described below; Upgrade
and DBSwitch remain unqualified as installed provider workflows. Unit tests and tests against
the three supported Kubernetes API servers exercise identity checkpoints,
interruption/retry, child provenance, failed children and stale completion.
They do not qualify actual kubelet rollouts, database transitions or provider
upgrade compatibility. Installed qualification remains tracked in
[issue #20](https://github.com/Alien6-Studio/hankoshell-operator/issues/20), with no
future release version scheduled. These workflows are available, but are
outside the first release's qualified core IAM contract.

The required installed-system test on Kubernetes **1.37.0** and HTTPS Keycloak
**26.8.0** exercises same-namespace Clone from an external source as a configuration
alias, with `includeData: false` and a configuration snapshot. A separate namespace
uses the exact scanned operator image and a read-only `view-realm`, `view-clients`,
`view-identity-providers` chart identity. The separate source inventory identity
adds `view-users`: complete import coverage reads the group inventory as well,
even when it is empty, and this role also permits target-realm user reads. The
fixture proves group reads succeed while client writes remain denied. It removes only the
operator's ConfigMap-create permission, waits for real persisted operation and
snapshot checkpoints, stops the manager, restores that permission and restarts.
Completion requires the original child UIDs, immutable capture hash, complete
import and current-generation verified-TLS target observation. Separate installed
cases refuse a foreign target and propagate an actual denied inventory read as
failed import/operation; the original realm and application must remain unchanged.
This subset does not qualify managed-source Clone, another Kubernetes/Keycloak
cell, arbitrary provider configuration, data copying, automatic rollback or
Upgrade/DBSwitch. The wider API/fault matrix and #20 remain separate requirements.

`Upgrade` changes the managed instance image; it does not establish provider or
database upgrade compatibility. `Clone` creates an external instance alias
reusing the source administrative connection and imports supported configuration;
it does not provision a new
database. `clone.includeData: true` and cross-namespace targets are refused;
administrative and TLS CA Secret references remain in the source namespace.
The alias retains the source TLS CA reference without enabling master hardening
or credential rotation. `DBSwitch` changes
the database Secret reference without migrating data. Operation `dryRun` skips
planned steps; it does not validate provider compatibility or recoverability.
These operations are not a tested disaster-recovery workflow.

Before the first mutation, status records the operation generation, intent hash
and source instance UID. Each child carries the operation's UID ownership and
intent marker; status records its UID and generation before consuming its result.
An acknowledged or lost-acknowledgement create is recovered by reading the exact
owned child. Foreign, replaced, edited or deleted checkpointed children fail the
operation; failed snapshots and incomplete/failed imports never advance it.
Database/image patches are idempotent on retry, and status-write errors propagate.

Completion requires the owned Deployment's current generation, desired image and
database reference, all desired replicas updated/ready/available with no old
replicas, and current-generation Admin API observation. Clone validates the
target alias, not the source. These observations are not an atomic transaction
with Kubernetes or Keycloak and do not prove database consistency.

For managed instances, `status.managedObservation` binds a successful Admin API
probe to the Deployment UID and generation. The instance controller requires an
owned, fully ready rollout with the desired image/database/replicas through the
uncached Kubernetes reader before probing, then verifies the same rollout again
before persisting Ready. It clears the previous binding while probing and on
failure. A successful response from old Pods during an in-progress rollout is
therefore insufficient. Operation validation reads the rollout again and requires
the identical binding, even when `WaitRollout` was already checkpointed as Done.
Replacement, changed or no-longer-ready Deployments require a new bound probe.
This fences the observations; it does not attest endpoint routing or create an
atomic snapshot of Kubernetes, networking, Keycloak and the database.

**Managed-status migration and rollback:** apply the updated CRD before the
operator. Existing managed Ready records without this binding cannot complete
in-flight Upgrade/DBSwitch operations; allow the instance controller to observe a
ready rollout and probe again. Do not write the binding manually or clear an
operation checkpoint. Existing terminal operation records remain historical.
An older operator does not enforce this binding, so suspend managed lifecycle
operations before rollback and inspect any in-flight effects before resuming on
an operator that enforces it. The real API and TLS regression tests for these
guards do not qualify installed managed rollouts, provider version compatibility,
database switching/migration or recovery; those #20 requirements remain open.

Managed infrastructure updates also require the exact current instance controller
owner (UID, name, kind and API version) on the Deployment, Service, NetworkPolicy
and PodDisruptionBudget. The controller reads that authority through the uncached
API and binds patches to its resourceVersion. Single-replica cleanup deletes only
an owned budget with UID and resourceVersion preconditions. An unowned, foreign,
deleting or concurrently reassigned object blocks the affected reconcile; it is
not an adoption request. Earlier owned writes in the same reconcile are not
transactionally undone.

**Infrastructure migration and rollback:** managed objects created by the operator
already carry their instance controller owner. A recreated instance or a legacy
manually provisioned homonym may now be refused. Inspect its ownership and effects
and use the explicit adopted mode for externally managed workloads; do not add an
owner merely to force an update. Preserve foreign resources and resolve names
before resuming managed reconciliation. An older operator lacks these write/delete
guards, so suspend managed reconciliation before rollback when foreign or
reassigned objects may be present. Real API race tests qualify the conditional
writes, not a production rollout or a database transition.
The instance itself is read through the uncached API; deletion stops this
reconciler before administrative activity or infrastructure writes. This does
not undo earlier effects and does not replace Kubernetes garbage collection.

Do not edit an in-flight specification to retarget or cancel it. A changed intent,
recreated source or legacy in-flight status without identity checkpoints is
refused. Inspect the source and children before creating a new operation; do not
clear checkpoints to force replay. Deleting an operation stops further steps and
permits Kubernetes garbage collection of its owned children, but does not undo
instance patches, imported resources or external effects. No automatic rollback,
deadline or mutual exclusion between administrator-submitted operations is
provided by this checkpoint contract.

Operation children preserve both the value and presence of the parent's tenant
label. Standalone operations leave the label absent; they do not synthesize an
empty label on snapshots, aliases or imports. Checkpoints also distinguish an
explicit empty tenant label from an absent one. Existing in-flight children made
by an older operator with a synthetic empty label may fail exact-scope validation;
inspect their status and effects before creating a new operation. The controller
does not relabel or reacquire such children to force continuation.

## Installed system test

Required CI installs the source chart and the exact scanned multi-architecture
image graph on a disposable kind Kubernetes **1.37.0** node, with real HTTPS
Keycloak **26.8.0** and an ephemeral private CA. The actual operator process uses
the chart's namespaced service account; its Keycloak service account has only
`manage-realm`, `manage-clients` and `manage-events` in the existing target realm.
Bootstrap administration provisions the fixture and independently checks results.
Normal reconciliation never uses the bootstrap credential.

This exercises installation/startup under Restricted admission, namespace RBAC,
readiness/write denial with a wrong Keycloak CA and recovery after trust repair,
realm/application/role reconciliation, Secret storage, Observe preservation,
drift recovery after a manager restart without duplicate clients or credential
rotation, and managed finalizer deletion. Denied master/user/identity-provider
administration and realm creation are asserted. Logs, events and CRDs are checked
for credentials. The mirror registry binds only loopback and retains the original
OCI digest; HTTP there is limited to disposable image transfer, while all
Keycloak administrative traffic uses verified HTTPS.

Reproduce with the fresh archive and evidence from the OCI security job:

```sh
python3 -m tools.bootstrap.install kind kubectl --directory /tmp/hankoshell-system-tools
GOBIN=/tmp/hankoshell-system-tools go install oras.land/oras/cmd/oras@v1.3.4
make system-test REVISION="$reviewed_revision" DIGEST="$scanned_digest" \
  OCI_ARCHIVE="$archive_path" OCI_EVIDENCE="$evidence_directory" \
  SYSTEM_OUTPUT="$report_path" KIND=/tmp/hankoshell-system-tools/kind \
  KUBECTL=/tmp/hankoshell-system-tools/kubectl ORAS=/tmp/hankoshell-system-tools/oras \
  OPENSSL="$(command -v openssl)"
```

Use pinned Helm 3.17.0, OpenSSL 3, the Python requirements and a running Docker
daemon. Only uniquely named test-owned clusters/containers are removed. The
single-node/dev-file fixture does not qualify production database operations,
CNI/CSI, cloud providers, browser login, enterprise fleet integration or recovery.
kindnet does not enforce NetworkPolicy; the separate chart/API tests check its
configuration, while installation-specific enforcement still needs qualification.

## Release rehearsal and publication

Version `1.0.0` has not been published. Source, chart and build metadata use
the same version; the development status in `versions.json` blocks publication. All implemented capabilities and canonical Attest hardening
remain intact. Workload Identity, Delegation & Agent Identity, Provider Portability, Fleet Reconciliation and Initial Public Contract Stabilization and #21's real trust evidence are required before
first publication; see the [Release 1.0.0 milestone](https://github.com/Alien6-Studio/hankoshell-operator/milestone/11) and
[release qualification](qualification.md#packaging-and-historical-upgrades).

The parser accepts normal `v<SemVer>` tags and extracts `1.0.0` from `v1.0.0`.
Parsing is separate from permission to publish: production eligibility and
promotion fail closed while source maturity is development. Only reviewed source
metadata declaring the release ready can enable the future path.
No environment variable or CLI option overrides that decision. Development
rehearsal shares retry logic only with a loopback registry and in-memory GitHub
storage; it cannot publish to GHCR or create a real GitHub Release.

The future normal release requires a GitHub-verified source commit and signed
annotated `v1.0.0` tag bound to that exact commit on protected main. Eligibility
checks ancestry, signatures, lightweight tags and moved/conflicting identities;
these checks run again immediately before publication. Git metadata responses
remain bounded to 1 MiB without fetching the commit diff. The signed root and
GitHub-signed protected squash merges preserve the technical history; sign-off
trailers are not signatures. Delivered artifacts additionally require Sigstore
and native Continuum Attest verification. Publishing a verified GitHub draft
remains a separate manual step. No tag is created by the workflow.

Required CI builds one AMD64/ARM64 OCI archive with BuildKit SBOM/provenance,
scans its exact manifests, and passes that immutable artifact ID to the release
rehearsal. The rehearsal shares packaging code with publication: chart metadata,
generated CRDs, digest-pinned values, curated notes, artifact names and checksums
are checked. Native pinned cosign signs the checksum payload with an ephemeral
local key; OpenSSL verifies the signature and rejects tampering. Native Continuum
Attest signs and timestamps the delivery using an ephemeral Ed25519 identity and
loopback RFC 3161 TSA. All five native checks and a tamper rejection must pass.
Native ORAS and Helm then exercise checkpoint storage/restore and package
promotion in an isolated registry. The test loses the acknowledgement after each
publication write, resumes the delivery and checks that completed writes are not
repeated. GitHub draft/asset storage is an in-memory fixture, not a production API
test. Conflicting release assets must fail before any publication write.

To reproduce with the **fresh archive/evidence from the OCI security job**:

```sh
bash tools/bootstrap/install_cosign.sh /tmp/hankoshell-rehearsal-tools/cosign
bash tools/bootstrap/install_attest.sh /tmp/hankoshell-rehearsal-tools/attest
GOBIN=/tmp/hankoshell-rehearsal-tools go install oras.land/oras/cmd/oras@v1.3.4
make release-dry-run REVISION="$reviewed_revision" DIGEST="$scanned_digest" \
  OCI_ARCHIVE="$archive_path" OCI_EVIDENCE="$evidence_directory" \
  DRY_RUN_OUTPUT="$fresh_output_directory" \
  COSIGN=/tmp/hankoshell-rehearsal-tools/cosign \
  ATTEST=/tmp/hankoshell-rehearsal-tools/attest ORAS=/tmp/hankoshell-rehearsal-tools/oras \
  OPENSSL="$(command -v openssl)"
```

Use OpenSSL 3, pinned Helm 3.17.0 and the Python dependencies in
`tools/requirements.txt`. The report is explicitly `publishable: false`; its
keys, TSA and Artifact Hub ID are fixtures. No private key is retained in its
artifacts. It writes only to its disposable loopback registry, never creates a tag/GitHub Release or
changes Artifact Hub. The local signature proves payload binding, **not** GitHub
OIDC/Fulcio/Rekor trust. Production image signatures remain keyless Sigstore with
issuer `https://token.actions.githubusercontent.com` and exact certificate identity
`https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/v1.0.0`.
The workflow uses the actual `GITHUB_WORKFLOW_REF` and eligibility requires
`github.ref == refs/tags/<tag>`; a main-ref run cannot claim this tag identity.

Before publication, maintainers must configure the real Attest signing secret,
trusted public key/ID, RFC 3161 endpoint and pinned TSA certificate in the
reviewed `release` environment, register the OCI chart in Artifact Hub and set
its assigned repository UUID, and verify public registry access. See the README
release configuration. The rehearsal does not qualify these external settings.
The configuration preflight requires the checksum-pinned Attest binary and
OpenSSL. It parses the Ed25519 PKCS#8 private key over stdin, compares its derived
public key, derives the canonical Key ID through native Attest using public
material only, and parses the TSA X.509 certificate. A retry rechecks that Key ID
before trusting its restored receipt. Tool diagnostics are captured and discarded
on failure; no private key is passed in command arguments or retained by preflight.
These checks establish configuration consistency, not administrative approval of
the signer or TSA. Independently review the public key/ID and the TSA issuing
certificate fingerprint, then verify a real endpoint-issued RFC 3161 token
against that pinned issuer. Successful certificate parsing alone does not prove
that the endpoint uses it. The rehearsal separately rejects wrong keys/IDs,
malformed certificates, an unrelated TSA certificate and a failing TSA endpoint;
its ephemeral authorities remain nonproduction fixtures.
Artifact Hub Verified Publisher establishes ownership, not vulnerability absence
or a chart signature. The named Attest key link is not Helm OpenPGP `.prov` signing.

Publication consumes the same scanned archive without rebuilding, stages it under
a non-release reference, verifies real image/blob Sigstore signatures and strict
Attest delivery evidence, then promotes the digest, chart and catalog metadata.
Before promotion it commits the archive, packaged chart, signatures, checksums
and Attest evidence under `delivery-candidate-1.0.0`, an explicitly non-release
OCI checkpoint. Every retry resolves that reference once, restores it by digest
and reuses its exact bytes rather than rebuilding/repackaging them. A different
source revision or conflicting candidate is rejected. Do not delete or retag the
checkpoint to force a different delivery through.
Release qualification restores that same archive before the OCI scan, installed
system test and rehearsal, so a retry tests the committed image rather than a
newly built substitute. Ordinary PR CI still builds and scans its own image.

Every attempt performs a fresh Trivy scan of the committed AMD64/ARM64 archive
under the current policy, re-verifies the existing image and checksum Sigstore
signatures, and recomputes the original Attest receipt with the configured trusted
signer/TSA. Historical signed scan reports retain their original timestamps and
do not satisfy the fresh gate. If the candidate is now vulnerable or its trusted
signer has changed, publication stops; an administrator must review the incident
and prepare a separately reviewed version rather than overwrite this version.
Current-attempt scan reports are retained separately as the Actions
`release-revalidation-<run>-<attempt>` artifact, including failed verdicts. They
do not replace the original signed release evidence.

Only matching versioned image digests, chart bytes, catalog metadata and draft
assets are reused. Missing writes are resumed; conflicting content fails during
preflight, without overwriting it. Matching published releases are read-only.
An interrupted upload that succeeded remotely is recognized on retry. GitHub
can also leave an empty `starter` asset after an upstream upload failure. Only
that zero-byte placeholder, under an expected filename in a matching draft, is
deleted and retried; complete or nonempty conflicting assets are never replaced.
See [GitHub's upload failure contract](https://docs.github.com/en/rest/releases/assets#upload-a-release-asset).
GitHub
draft creation remains after verified package promotion. These writes are not
atomic: later failures may leave verified packages or a partial draft available.
Actions concurrency serializes release workflows; other registry/release writers
are trusted administrators and must not race this workflow.

## Upgrade and rollback

Apply the [API conversion, migration and rollback policy](api-migration-policy.md)
and review the [per-resource support inventory](api-support.md). CRDs precede
new operator fields; Helm rollback alone does not downgrade stored state.
The Conditions topology change has a separate writer-ownership migration and
does not establish public cross-version compatibility.

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


## Organization provider readiness and optional projection

`HankoOrganization` manages Keycloak groups, additive realm/client-role mappings,
and native tenant-root Organizations with domains and configured IdP links.
Standalone reconciliation needs no hankoShell API: `Phase=Ready`, `Synced=True`,
and `Projection=Unknown` with reason `Disabled`. `PositionID` is optional,
last-known platform metadata and never authorizes provider adoption or deletion.

Projection is installation-wide. Helm always renders
`HANKO_ORGANIZATION_PROJECTION_ENABLED` from `organizationProjection.enabled`.
Disabled mode mounts no API token, emits no API URL and opens no projection
network egress. Enabled mode requires `organizationProjection.apiURL`, the
existing token Secret/key and explicit API destination/ports. Enterprise requires
verified HTTPS even if the API is unavailable. Standard mode retains the existing
HTTPS or cluster-local HTTP endpoint policy; administrative API tokens and traffic
remain sensitive, so prefer HTTPS.

For direct deployments, set the environment switch to the literal `true` or
`false`. True requires `HANKO_API_URL` and `HANKO_API_TOKEN`, supplied through a
Secret. False requires removing both values; leftover credentials/URL or an
invalid boolean fail startup. If the switch is absent, a nonempty legacy API URL
with a token temporarily enables projection and emits a bounded migration notice.
No URL and no token disables projection. Credentials in URLs are rejected.

| Outcome | Phase | Synced | Projection |
| --- | --- | --- | --- |
| Provider ready, projection disabled | Ready | True / Reconciled | Unknown / Disabled |
| Provider and configured projection ready | Ready | True / Reconciled | True / Reconciled |
| API call fails | Error | True / Reconciled | False / ProjectionFailed |
| Enabled projector unavailable | Error | True / Reconciled | False / ProjectorUnavailable |
| Parent provider not ready | Pending | False / ParentPending | Unknown / ProviderPending |
| Provider ready, parent projection pending | Pending | True / Reconciled | False / ParentProjectionPending |
| Provider fails | Error | False / provider failure reason | Unknown / ProviderPending, or Disabled |

Children require a current provider-synchronized parent group ID/path in the same
realm, not a parent Phase or PositionID. Projection separately requires a current
successful parent Projection condition and PositionID. A parent's API failure
therefore cannot block child Keycloak convergence. Provider IDs and successful
Synced evidence are persisted even when the API subsequently fails. Repeated
projection retries read the owned provider state without rewriting matching state.
`observedGeneration` identifies the latest processed status, including failures.

Disabling an existing projection retains PositionID without API writes. On
subsequent deletion the operator verifies UID ownership, removes owned Keycloak
state and proves absence, then removes its finalizer without API access. A bounded
warning Event/log reports that external position cleanup requires administrator
review; it contains no token, endpoint or PositionID. Administrators must review
and remove any residual platform position separately.

With projection enabled, provider cleanup still happens first. A failed Position
deletion leaves `Synced=True/Deleted`, `Projection=False/ProjectionFailed`, Phase
Error and the finalizer for retry. Missing API positions are idempotent success.
Provider objects already proven absent are read but not deleted again or recreated.
A failed Kubernetes status/finalizer write is retried; Keycloak and Kubernetes are
not transactional. Provider IDs remain last-known cleanup metadata until deletion.

Objects created by the operator retain their UID markers. Unmarked groups/native
Organizations previously adopted solely by path or alias require administrator
review; status or PositionID alone cannot authorize adoption/deletion. Existing
reserved authority-role, protected-realm and effective-closure checks remain active.
Organization separation adds no Keycloak permission. A bounded child-presence
read under existing group authority prevents recursive deletion of descendants;
clean child organizations first and review/remove foreign children separately. Use the
existing organization/group profile in [the permission contract](keycloak-permissions.md).
The group API's `manage-users` role also grants target-realm user authority; this
Keycloak limitation is unchanged and should be isolated to the intended realm.

## Runtime application delivery

Use [runtime bindings](architecture/application-identity.md#runtime-bindings) for
versioned workload metadata and optional confidential OIDC credentials. Targets
pre-exist and authorize the exact application UID, binding, ServiceAccount name/UID
and target type. Grant get/patch only to named targets in their namespace, with get
only on the named ServiceAccount. No target list/watch/create/delete or workload
mutation is needed. A metadata ConfigMap grant does not authorize Secret delivery.

Last-known outputs survive provider outages; they are not then proven current.
Consumers must check Ready and matching revisions across ConfigMap and Secret
because their updates are not atomic. Removing consent stops delivery and also
blocks cleanup; administrators must explicitly resolve CleanupConflict and revoke
provider credentials during an incident. ServiceAccount replacement requires fresh
UID consent. This is controlled credential delivery, not token federation.

## Workload identity native qualification

Native workload qualification defines the [workload identity contract](architecture/workload-identity.md)
and adds a required real kubelet/Keycloak matrix for 1.35.0/1.36.2/1.37.0 and
26.7.5/26.8.0. These disposable fixtures prove projected 600-second assertions,
rotation/expiry, native permissions, method exclusivity and negative inputs.
The native fixture uses production reconcilers with ephemeral Hanko storage and
real workload API UID reads; installed regression separately proves activation.
The installed workload qualification below proves workload-to-resource
authorization separately and retains both earlier layers.
Existing application runtime anchors remain credential delivery, not federation.

Native Keycloak accepts same-name recreated SAs and reusable assertions, without
TokenReview. Workload binding and mesh coherence therefore uses explicit SA UID approval
and fresh local containment, with a documented residual revocation interval.
Use the contract's two-client migration when authentication proof must precede
secret deactivation. The operator will configure trust/metadata without storing
workload JWTs or injecting PodSpec projections. #21 production trust and the
first-publication release gate remain unchanged.

## Installed workload identity qualification

Workload Identity is qualified on Kubernetes **1.35.0 / 1.36.2 / 1.37.0** with
Keycloak **26.7.5 / 26.8.0**. The required `installed-workload` matrix installs
Helm with the exact scanned OCI index/digest from its CI revision; it does not
rebuild a manager or substitute a different artifact. All six cells run real
restricted Pods with dedicated SAs, automount disabled and read-only projected
600-second assertions for the exact Keycloak realm audience. A Pod exchanges its
assertion for a live access token, then submits that same token to native UMA for
declared resource ALLOW and undeclared resource DENY. Authentication failures and
network errors never count as authorization denials.

The six cells also prove retained-secret refusal, negative assertion inputs,
actual kubelet rotation and expiry, same-name SA recreation, native name-based
acceptance while reconciliation is stopped, asynchronous owned-client containment,
no automatic reactivation, exact named RBAC and credential/JWT leakage inspection.
Two-client migration retains the old working Secret client until explicit consumer
cutover and retirement. The native 6×57 capability matrix and general installed
19-check regression remain mandatory.

The two deep cases use **Kubernetes 1.37.0 with each Keycloak version**. They
exercise typed CoordinatedCutover and canonical approval/review/cleanup, same UUID
and credential across Secret → Kubernetes → Secret → Kubernetes, five journal
restart boundaries and external provider/API fault proxies. Accepted CREATE/PUT,
Secret/ConfigMap patches, status and finalizer responses are genuinely dropped;
externally removed status is separately identified. Output consent/UID/immutable/
version conflicts, provider outage, trust drift, effective flow refusal and foreign
preservation are exercised without production test hooks. These deeper scenarios
are qualified on two cells, not all six.

Reproduce a single cell using a fresh OCI archive and evidence from its CI run:

```sh
make workload-installed-test \
  KEYCLOAK_VERSION=26.8.0 KUBERNETES_VERSION=1.37.0 \
  OCI_ARCHIVE="$archive_path" OCI_EVIDENCE="$evidence_directory" \
  DIGEST="$scanned_digest" REVISION="$source_revision"
```

Kubernetes 1.37.0 enables the deep scenarios. Required source, API/native matrices,
OCI security on AMD64/ARM64, CodeQL Go/Python/Actions, general installed regression
and nonpublishing release rehearsal all remain gates. Uploaded evidence is a
public allowlist of versions, revision/digest, case decisions, UID hashes, times
and counts; detailed diagnostics remain local/nonpublishable. No credentials,
assertions, raw native/Secret bodies, kubeconfig or private keys are uploaded.

Native UID matching is still name based and assertions are replayable. Access
tokens can outlive assertion acceptance; disabling a client does not instantly
revoke them. Polling and outages extend asynchronous containment. Same-client
cutover has no zero-downtime guarantee. This adds no TokenReview authenticator,
remote binding, SPIFFE, delegation/token exchange or Pod injection, and does not
qualify production CNI/database/cloud recovery. Development version/status and #21
initial-publication trust requirements remain unchanged.

## Workload binding configuration

Use the [Workload binding and mesh coherence contract](architecture/workload-identity.md#workload-binding-and-mesh-coherence)
for the required live ServiceAccount UID, explicit client source and optional
pre-existing ConfigMap UID consent. A minimal Helm cross-namespace grant is:

```yaml
workloadBinding:
  grants:
    - namespace: workloads
      serviceAccounts: [worker]
      configMaps: [worker-identity]
```

The workload owner creates the ServiceAccount/ConfigMap and supplies consent.
The binding controller uses named uncached reads and only patches its public
metadata field. It adds no TokenRequest/TokenReview, token Secret, Pod mutation,
ConfigMap creation or wildcard cross-namespace watch. Projection duration must
fit the shared trust age. Binding readiness precedes native activation; do not
infer token issuance or workload authentication from either readiness or metadata.

UID loss clears current readiness and attempts enabled-only containment of the
strictly owned native federated client. Normal polling is 30 seconds; API/provider
outages can extend the interval and issued access tokens survive native client
disabling according to their own lifetime. Lost consent/UID holds field cleanup
for explicit administrator resolution. Review the [native credential powers and
same-process limits](keycloak-permissions.md#workload-identity-qualification).

## Structural authorization explanation

`HankoResourceServer.status.authorizationExplanation` shows bounded provider-proven
allow structures, not a live user decision. Its source, generation and plan/read
hashes distinguish current applied proof, observation and retained historical
proof. `AuthorizationExplained` is independent of `Synced`. Optional role-provenance
read failure does not change a synchronized grant or trigger policy writes.

Configure the explicit [read profile](keycloak-permissions.md#optional-structural-role-provenance-reads)
if organization-mapped/composite origins are needed. view-users reads users as well
as groups in the target realm. Native authorization, unknown bindings and truncated
paths prevent a complete structural account. No users, memberships or tokens are
exported. Existing provider UUID grants can remain during reconciliation failure;
this evidence does not guarantee instantaneous revocation or token invalidation.
See the [implemented contract](architecture/organizational-authorization.md#bounded-effective-explanation).

For existing-Keycloak discovery, use a separate external-mode instance with a
reviewed HTTPS endpoint/CA and a dedicated inventory AdminRef. HankoImport resolves
sourceRef through the direct API reader and never falls back to a shared writer
pool. [The inventory permission matrix](keycloak-permissions.md#dedicated-inventory-identity)
explains native role privacy limits on 26.7.5/26.8.0. Terminal Done is not evidence
of full coverage; inspect InventoryComplete, coverage and typed target candidates.
These candidates do not approve provider ownership or a transition to Manage.

## HankoServiceAccount federated authentication operations

Install the updated HankoServiceAccount schema before controller upgrades. Existing
manifests with omitted authentication retain Secret behavior. Review the
[activation and migration contract](architecture/workload-identity.md#hankoserviceaccount-federated-authentication)
and [credential authority limits](keycloak-permissions.md#hankoserviceaccount-federated-authentication).
The client writer is separate from the trust writer and dependent reader; the
current manager process can access their combined native powers.

Prepare the workload's dedicated ServiceAccount, exact UID, projection audience,
short lifetime and runtime configuration yourself. The operator never modifies
PodSpec or requests/receives workload JWTs. Named ServiceAccount reads and public
ConfigMap field patches add no TokenRequest/TokenReview authority. Ready and active
metadata prove configuration; test actual workload authentication and separately
declared API permissions before switching consumers. Prefer two-client migration;
same-client cutover may interrupt consumers and requires exact current external
approvals, a durable journal, explicit authentication review and output cleanup.

Do not drop Kubernetes binding authority to force Secret mode. Explicit fallback
retains the binding, stages and verifies the same native recovery credential before
an approved method switch, and never generates a replacement on missing credentials.
Keep the canonical output UID and owner intact. Revoked approval/consent, immutable
or replaced outputs, unexpected native fields and unfinished rotations stop the
transaction. Resolve ambiguous attempted rotations explicitly; replay is refused.
Issued access tokens retain their own lifetime after containment or authenticator
changes. The existing native UID/replay limitations and residual revocation interval
still apply. Installed-system qualification proves Pod-to-resource authorization
and deep restart/recovery on the documented matrix; no release/publication is added.

## Experimental lifecycle approval

`HankoOperation` / `HankoSnapshot` are excluded from the stable 1.0 contract by
[ADR-011](architecture/decisions/ADR-011-experimental-lifecycle-authority.md).
They retain their experimental v1alpha1 schemas. The chart defaults to
`lifecycle.enabled: false`, removes their complete resource/status/finalizer RBAC
and registers neither controller. Its independent admission guard remains active
while disabled. The raw binary defaults to `--lifecycle-enabled=false`.

Before enabling or upgrading pending work, stop submissions, inspect the exact
operation/snapshot spec, source instance and owned children, and retain their
UID-bound checkpoints. Remove any pre-existing approval whose independent origin
cannot be established. Do not delete children or rewrite checkpoints to make an
old operation resume. A malformed/legacy checkpoint still fails closed. Existing
accepted provider/database effects are not rolled back by disabling the writers.

Enable explicitly in reviewed Helm values:

```yaml
lifecycle:
  enabled: true
  adminGroups: [platform-lifecycle-admins]
```

Install/upgrade with the normal pinned image/chart procedure above and those
values. The installer must have admission-policy installation authority. Do not
grant membership of this administrator group to the operator or ordinary authors.
Raw installations must provision equivalent fail-closed admission protection
before enabling the process flag. Namespace Secret writers remain separately
trusted; DBSwitch accepts only a dedicated PostgreSQL configuration Secret in the
same namespace/tenant scope with exactly the four reviewed `KC_DB*` fields in
ADR-011. Backup Jobs retain their dedicated Secret/image/PVC guards. Never put
credentials in an approval annotation or diagnostic artifact.

An ordinary author may submit a request; it waits with current
`Authorized=False/ApprovalRequired`. No children or execution checkpoint are
created. As the independent administrator, first review the spec and source:

```sh
kubectl get hankooperation upgrade -n auth -o yaml
kubectl get hankokeycloakinstance source -n auth -o yaml
kubectl get hankooperation upgrade -n auth -o json   | python3 -m tools.operations.lifecycle_approval > lifecycle-approval.json
cat lifecycle-approval.json
kubectl patch hankooperation upgrade -n auth --type=merge --patch-file=lifecycle-approval.json
```

Use `hankosnapshot` for an independently requested snapshot. The patch contains
only public UID/generation/intent/source bindings. The helper prepares it without
contacting Kubernetes; it does not approve or execute the request. Review the
source and intent before applying it with administrator credentials. The runtime
recomputes the binding and refuses stale/cross-object approvals. A child
configuration snapshot uses only its currently approved parent Snapshot step;
there is no general inherited approval for arbitrary backup work.

Remove authority to suspend **further** effects:

```sh
kubectl annotate hankooperation upgrade -n auth hanko.sh/lifecycle-approval-
```

A previously accepted Job or image/database patch continues independently; inspect
actual state before recovery. Do not call this command rollback. A spec/tenant
change or object/source recreation invalidates approval. Approval changes enqueue
immediately and are rechecked before effect boundaries; cross-object API reads
and writes are not a distributed transaction. Re-enable only after reviewing the
same intent and existing child identities. No bulk approval or checkpoint reset
is a supported recovery procedure.

Validation: `make chart-check` lints and renders the chart;
`checkLifecycleAdmission` exercises independent admission on all supported real
API servers; `TestLifecycle*` exercises exact authority/revocation/Secret refusal.
`tools/qualification/scenarios/system_test.py::lifecycle_alias` exercises opt-in, approval wait and
administrator patch, ConfigMap-create denial, restart and stable child UIDs on a
real installed configuration-only Clone. These commands are administrator
procedures; installed managed Upgrade/DBSwitch and portable restore remain
explicitly unqualified. No production evidence is claimed.

The exact active qualification window is generated below. Earlier version-specific
permission, protocol and installed evidence records remain historical qualification
snapshots and must be reviewed before promoting new pins. See [support policy](support-window.md).

<!-- support-window:start -->
| Component | Exact qualification versions | Default |
| --- | --- | --- |
| kubernetes | `1.35.0`, `1.36.2`, `1.37.0` | `1.37.0` |
| keycloak | `26.7.5`, `26.8.0` | `26.8.0` |
<!-- support-window:end -->

## Executable CRD and RBAC review inventory

Review [the validation/grant inventory](security-surface.md) and its migration
notice before applying the candidate CRDs. Preflight freezes all served schema
hashes and four rendered RBAC profiles. The inventory records remaining bound
and authority gaps; it does not accept them. Native lease election is exercised
with only CREATE and exact-lock GET/UPDATE on real Kubernetes API servers.
