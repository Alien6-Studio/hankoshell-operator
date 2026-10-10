# Changelog

## 0.5.0 — Unreleased

- Add #49 Organization Observe/Manage and target-local aggregate candidates.
  Bind live realm/group/path/parent and optional native Organization UUIDs;
  write the same owner-only receipt at separate group/native checkpoints.
  Recover partial acquisition, lost acknowledgements and status loss without
  duplicating completed checkpoints. Root Organizations in external realms
  require the feature to be enabled already.
- Add selective ResourceServer V2 journals with exact owned IDs, realm/Application
  identity and an embedded common receipt, preserving the Application receipt.
  Block foreign incoming dependencies and unqualified selected native fields;
  retain valid V1 reconciliation/recovery/cleanup without cosmetic migration.
- Qualify explicit adopted-to-Manage after current ownership/preservation checks.
  Keep acquisition Observe and the imported latch until explicit administrator
  action. Source/approval annotations are not lifetime authority; live receipts
  and journals recover ownership after status loss. Owned children can reconcile
  inside external/Observe realms without acquiring the realm lifecycle.
- Preserve closed native locale metadata, safe OIDC/SAML settings, foreign
  mappers/client roles, additive role composites and Organization mappings,
  children/members/domains/IdP links. Reject opaque or sensitive native state;
  document all milestone-native families without claiming general provider
  coverage. Recover existing service credentials only after explicit Manage.
- Hold destructive cleanup on foreign client children/authorization boundaries,
  Organization children/members/mappings/links, unsafe graph sharing or unproven
  adopted-role reference absence. Keep finalizers on ownership conflicts after
  status loss; resolve Organization cleanup identities from live path/alias
  rather than status UUIDs, including partial child-first cleanup. V2 graph cleanup retains the client, sibling receipt and enabled
  Authorization Services; Observe deletion preserves provider state.
- Reconstruct a managed service account's SecretRef after status loss when its
  credential projection already exists, without provider credential reads or
  rotation.
- Extend the installed scanned-image system test through acquisition, explicit
  Manage, native preservation, restart/status recovery, drift repair and safe
  cleanup/refusal with separate Organization and authorization writer profiles.
  Final #49 source/image/matrix qualification remains in progress; no 0.5 tag
  or public package has been created. GO-2026-5932 remains UNKNOWN/unfixed and
  unsuppressed.

- Implement #48: explicit target-local source/contract/candidate approval for
  lossless OIDC/SAML application, role and service-account ownership acquisition.
  Revalidate current Kubernetes/provider identity and bounded candidate through
  an independent reader; write only owner + canonical provider receipt, verify
  unchanged UUID/business semantics, and remain Observe. Recover lost HTTP
  acknowledgements/status checkpoints without another PUT; partial or conflicting
  state never authorizes semantic writes or rollback.
- Add Manage/Observe to roles/service accounts and retain imported Observe latches.
  Unqualified native state remains behind ManagePreservationUnqualified.
  Observe deletion preserves the provider and adds no finalizer/Secret.
  Legacy application UUID/observation migration remains compatible; combining
  legacy and common approval conflicts before writes.
- Harden service-account clients and token mappers with distinct kind/UID owner
  envelopes and fresh checks before writes, secrets, rotation and deletion.
  Existing unmarked M2M clients require explicit reviewed acquisition; matching
  clientID, Secret, status or finalizer no longer grants implicit authority.
- Include only exact qualified Keycloak defaults realm_client=false,
  backchannel.logout.session.required=true and
  backchannel.logout.revoke.offline.tokens=false in canonical read-only evidence.
  Other values/native state remain refused. Keep native client-scope collections
  unqualified; avoid reattaching service_account during ownership-only PUT.
  Qualify HTTPS 26.7.5/26.8.0, Kubernetes 1.35.0/1.36.2/1.37.0 and an installed
  scanned-image import/acquisition path. Packaging remains 0.4.0.

- Implement #47: bounded existing-Keycloak discovery, observation and typed
  adoption diff. Add the evidence-only `hanko.sh/adoption-contract/v1alpha1`
  candidate on applications, imported roles, service accounts and safely observed
  resource servers. Domain-separated hashes bind current target UID/generation,
  provider instance/trust/realm/object identities and classified non-secret state.
- Make HankoImport sourceRef authoritative through a direct APIReader and named
  credential/CA Secret GETs; never use the shared writer pool as fallback. Add
  independent InventoryComplete coverage, bounded inventory summaries and counts.
- Generate qualified SAML Observe applications and ordinary Observe HankoRole
  inventory; include client roles/composites/mappers, groups, native Organizations,
  brokers and bounded Authorization Services graphs without reading users,
  memberships or client-secret endpoints. Opaque credentials remain excluded;
  lossy native round trips and unresolved aggregate references are not approvable.
- Final aggregate/adopt-to-Manage qualification is tracked by #49.
  Packaging stays 0.4.0 during qualification. GO-2026-5932 remains
  UNKNOWN/unfixed and unsuppressed: the Go advisory contains no fixed version.

- Accept the existing-Keycloak adoption architecture: HankoImport remains
  discovery/Observe orchestration; target-local one-shot metadata approval will
  bind exact provider identity, complete semantic observation and a reviewed
  typed diff. Acquisition writes only ownership; Manage is a separate decision.
- Characterize owner-marker/journal preservation and destructive lifecycle
  boundaries on real HTTPS Keycloak 26.7.5/26.8.0. Retain arbitrary existing realm
  and opaque broker lifecycle as Observe-only; preserve legacy application
  UUID/observation migration syntax. No production adoption API is added.
- Create the discovery/diff, leaf ownership and aggregate/native qualification
  backlog. Current packaging remains 0.4.0; no 0.5 source tag or publication.

## 0.4.0 — Unreleased

- Accept the organizational authorization design: extend HankoResourceServer with
  an organization principal and explicit descendant semantics, preserving role
  composition without adding a CRD. Bounded
  structural explanation/provenance completes #42.
- Characterize real group-policy CRUD, UMA decisions, hierarchy changes, native
  Organization separation and least-privilege profiles on HTTPS Keycloak
  26.7.5/26.8.0. Fresh group ownership reads require explicit view-users authority;
  the standard profile is unchanged.
- Implement organization principals with direct-only default and explicit
  declared descendants, strict fresh UID/group/hierarchy ownership, uncached
  execution revalidation and bounded namespace dependency watches. Keep expanded
  provider UUIDs out of portable intent. Enforce 128 groups per permission,
  32 hierarchy edges and the existing 256-policy journal budget before writes.
- Reconcile typed group policies with extendChildren=false and no claim override,
  including drift, owned-only cleanup, status-loss recovery and mixed allow paths.
  Qualify real UMA/profile denials on HTTPS Keycloak 26.7.5/26.8.0, admission/watch
  behavior on Kubernetes 1.35.0/1.36.2/1.37.0 and an installed scanned-image path.
  Previous applied grants can persist until successful reconciliation; no instant
  revocation or automatic privilege grant is introduced.
- Expose provider-proven structural authorizationExplanation with Applied/Observed
  source, plan/observation hashes, direct/descendant organization paths, generic
  role/client paths and observed realm/client composite origins. Preserve overlap.
  Bound paths to 256 and ancestry/role chains to 32 edges; native/unknown state,
  missing optional reads and truncation remain explicitly incomplete. No subjects
  or secrets are exported and status remains evidence only.
- Keep optional deeper provenance independent of Synced and provider mutation.
  Qualify read-only failure, forged/historical status and exact-image installation.
- Align active source/release metadata to 0.4.0, a normal initial-development
  SemVer source boundary. Historical tags remain immutable; publication is #21.

<!-- release-notes:start -->
### Release overview

hankoShell Operator 0.4.0 reconciles declarative Keycloak IAM configuration from
Kubernetes. Application identity can live beside deployment manifests; Hub,
hankoShell API and Continuum are optional. Project: https://hanko.sh.


Organizational Authorization adds same-namespace organization principals, direct-only
by default, with explicit expansion to current declared owned descendants. Foreign
children and prefix collisions are excluded; every provider group definition is
direct-only. Existing role/client grants remain valid and overlapping allows stay
separate. Grants use an applied UUID snapshot: previous access can remain until
successful reconciliation; no instantaneous revocation or token invalidation is claimed.

ResourceServer status exposes up to 256 provider-proven structural alternatives,
with Applied/Observed source and bound plan/read/hash evidence. Direct/descendant,
generic realm-role, organization mapping and realm/client composite paths remain
distinct. Resource/action pairs follow observed bindings, not a desired Cartesian
product. Ancestry and role chains are bounded to 32 edges. Native policies, unknown
bindings, unavailable optional reads and truncation prevent complete=true. This
is structural explanation, not a per-user decision; no subjects or memberships
are exported. Historical proof remains identifiable when current reads fail.

Organization grants require explicitly provisioned target-realm view-users in
addition to manage-clients. view-users also reads target-realm users. Mixed role
provenance uses view-realm and existing client read authority. No new writer,
self-grant or realm-admin requirement is introduced; optional explanation failure
preserves otherwise synchronized authorization and induces no policy writes.

Application Identity supports OIDC SPA, confidential web and M2M clients, plus
qualified SAML SP-initiated POST with exact HTTPS ACS, signed responses/assertions,
bounded NameID formats, client roles and IdP metadata URLs. OIDC remains the
omitted-protocol default. Application and mapper ownership is bound to Kubernetes
UID; legacy unmarked clients require an administrator-reviewed exact provider UUID
and observation hash. In-place protocol conversion is refused.

HankoApplication runtimeBindings deliver a deterministic, versioned identity.json
ConfigMap and optional confidential OIDC client_secret into existing workload-owned
targets. Every target consents to the exact application UID, binding, current
ServiceAccount UID and target type. Resource-name-limited namespace RBAC grants
get/patch only; no new Keycloak permission is needed. SPA/SAML are metadata-only,
and Observe bindings are refused. There is no new CRD.

Delivery advances only from current proven applied provider state. bindingRevision
uses public metadata, plan/generation and non-secret Kubernetes identities/version
metadata, never secret bytes. Rotation updates canonical and workload credentials
and output revisions. Partial writes, acknowledgement loss and status loss converge
without repeating current client/mapper writes or credential rotation. Cleanup
removes managed fields only and requires fresh consent; revoked consent needs
administrator action. ConfigMap/Secret writes are nontransactional. Consumers check
Ready and matching revisions; no SDK, workload mutation or automatic restart is
provided. Legacy credential-only projections are preserved separately.

The existing IAM Contract Engine covers roles/resource-server plans, observations,
drift, capability refusals and owned cleanup. Standalone organizations reconcile
Keycloak groups/native Organizations independently of optional platform projection.
Status is evidence, not execution authority. No remote executable plan is exposed.

Qualification uses Kubernetes 1.35.0, 1.36.2 and 1.37.0 API/etcd fixtures; real HTTPS
Keycloak 26.7.5 and 26.8.0 including OIDC browser/PKCE, M2M and SAML signature/security
regression; and an installed exact-scanned-image system on kind 1.37.0 plus HTTPS
Keycloak 26.8.0 with runtime delivery, projected-credential token, rotation and
cleanup. Other versions, cloud/CNI/CSI enforcement, enterprise fleets and production
portable backup/restore are unqualified. Snapshot and lifecycle workflows remain
experimental and unqualified. Federation, projected SA JWT login, SPIFFE/token
exchange, live Hub binding execution, SLO, signed SP requests, encryption,
artifact/ECP and SAML attribute statements are deferred.

The 16 v1alpha1 APIs remain experimental. 0.4.0 is a normal SemVer version in
initial development, not a prerelease. Use verified HTTPS, a dedicated limited
Keycloak service account, referenced Secrets, namespace RBAC, Restricted pods and
explicit default-deny networking. Source govulncheck and exact AMD64/ARM64 image
scans are additive. The operator and embedded cosign are scanned. GO-2026-5932
remains an unsuppressed UNKNOWN/unfixed dependency advisory until upstream supplies
a compatible fix. No fixable HIGH/CRITICAL finding passes the image gate.

Supply-chain evidence distinguishes SBOM, provenance, vulnerability reports,
Sigstore signatures and Continuum Attest receipts. The signed source tag freezes
source only. Production publication remains pending in #21: no public chart, image
or GitHub Release is claimed. Install the source chart at charts/hankoshell-operator
with an explicitly configured HTTPS Keycloak URL, referenced credentials/CA when
needed and a reviewed immutable image. The future OCI chart path is
oci://ghcr.io/alien6-studio/charts/hankoshell-operator.

The standalone Hub authentication/integrity path uses HMAC tied to the bearer
credential, not an independent asymmetric signature. Enterprise Continuum policy
and optional platform integrations do not change runtime binding authority.
Provider reconciliation and Kubernetes output patches offer no transaction or
portable rollback guarantee. Review docs/architecture/application-identity.md,
docs/secure-deployment.md and docs/keycloak-permissions.md before migration.

Report vulnerabilities privately at
https://github.com/Alien6-Studio/hankoshell-operator/security/advisories/new;
SECURITY.md describes supported versions and response times.
<!-- release-notes:end -->

## 0.3.0 — Unreleased

- Add protocol-aware HankoApplication intent, sealed local plans, Keycloak adapter
  and bounded evaluation/apply/observation evidence using the IAM contract engine.
- Preserve the omitted-protocol OIDC default and existing flat OIDC fields. Add a
  qualified SAML POST subset: entity identity, exact HTTPS ACS, signed response
  and assertion, bounded NameID formats, shared client roles and metadata URLs.
- Bind application and mapper ownership to Kubernetes UID. Existing unmarked 0.2
  clients require reviewed exact UUID + observation approval; no automatic
  adoption or in-place protocol conversion. Preserve credentials and object IDs
  during unchanged approved OIDC migration.
- Qualify real OIDC browser/PKCE/M2M and SAML signature/security flows on Keycloak
  26.7.5/26.8.0, protocol admission/status on Kubernetes 1.35.0/1.36.2/1.37.0, and
  installed OIDC/SAML lifecycles in the scanned-image system fixture.
- Add bounded HankoApplication runtimeBindings: versioned ConfigMap identity.json,
  optional confidential OIDC credentials, exact application/workload UID consent,
  explicit target namespace RBAC, revision and target-preserving cleanup.
- Qualify drift, rotation, partial writes, lost acknowledgements and status-loss
  recovery without repeated current provider writes; preserve legacy projections.
- Align active chart/image/CI/evidence metadata to 0.3.0. Historical source tags
  remain immutable; production publication is pending in #21.
- Keep SLO, signed SP requests, encryption, SAML attribute statements, workload
  federation, automatic restart and live Hub binding execution deferred.



## 0.2.0 — Source frozen (unpublished)

### Release overview

hankoShell Operator 0.2.0 reconciles declarative Keycloak IAM configuration from
Kubernetes. Application identity configuration lives beside deployment manifests;
Hub, hankoShell API and Continuum integrations remain optional. Project: https://hanko.sh.

The IAM Contract Engine introduces locally compiled intent/provider-plan identities,
capability refusals, bounded provider observations and explicit drift for
HankoRole and HankoResourceServer. Applied generation/hash advance only after
successful Manage execution and acceptable read-back. Observe performs no writes
and cannot claim application. Status and connected DTOs are evidence, not authority;
there is no public Plan CRD or executable remote plan.

HankoOrganization reconciles nested Keycloak groups, realm/client-role mappings
and tenant-root native Organizations, domains and configured IdP links without
requiring a platform PositionID. Synced reports provider state. Projection reports
disabled, successful or failed optional API integration. Children converge in
Keycloak while parent projection is unavailable. Cleanup verifies owned provider
absence before configured API cleanup; disabled projection makes no API calls.

Qualification covers Kubernetes 1.35–1.37 with API-server/etcd fixtures 1.35.0,
1.36.2 and 1.37.0, real HTTPS Keycloak 26.7.5/26.8.0, and an installed Helm/operator
system on kind 1.37.0 plus HTTPS Keycloak 26.8.0. Other versions, browser login,
CNI/CSI/cloud enforcement, enterprise fleets and production database recovery are
unqualified. Snapshot and lifecycle APIs remain experimental and unqualified.

The 16 v1alpha1 APIs remain experimental. 0.2.0 is normal SemVer in
initial development, not a prerelease. Use verified HTTPS, a dedicated service account,
referenced Secrets, namespace RBAC, Restricted pods and explicit default-deny
networking. Source govulncheck and exact AMD64/ARM64 image scans are additive;
both operator and embedded cosign use patched Go/HTTP dependencies. Release
publication retains exact-image binding, Sigstore and Continuum Attest gates.
Hub synchronization authenticates bundle integrity with token-derived HMAC,
not an independent publisher signature. Enterprise transport requirements do
not qualify fleet operation. Snapshot backup/restore is not qualified as a
portable recovery mechanism.

For source installation, use charts/hankoshell-operator with an explicitly
configured Keycloak HTTPS URL, referenced credential Secret and an immutable
reviewed operator image. Production trust and public packages remain pending in
#21; the source tag does not claim a published chart, image or GitHub Release.
The future chart publication path is
oci://ghcr.io/alien6-studio/charts/hankoshell-operator, gated by reviewed delivery
evidence; it is not currently an installation source.

Migration: Helm renders organization projection explicitly. Direct installations
should set HANKO_ORGANIZATION_PROJECTION_ENABLED=true/false; legacy URL-only
configuration is temporarily supported with a migration notice. Explicit false
requires removing URL/token configuration. Disabling projection retains the
last-known PositionID; external residual cleanup belongs to the administrator.
Groups and native Organizations require matching ownership markers; unmarked
objects previously adopted by path/alias need administrator-reviewed migration.
Provider calls are multi-call/nontransactional and do not provide exactly-once
or portable rollback guarantees. Live IAM Hub evidence transport remains deferred.

Report vulnerabilities privately at
https://github.com/Alien6-Studio/hankoshell-operator/security/advisories/new;
see SECURITY.md for supported versions and response times.
See docs/secure-deployment.md and docs/keycloak-permissions.md for deployment,
permissions and migration limits.


- Build the operator and embedded cosign with Go 1.27.2 and patched HTTP/2
  dependencies; retain the source and exact-image vulnerability gates.

- Make standalone organization provider readiness independent of optional API projection.
- Add explicit projection configuration, separate Synced/Projection conditions and
  independent provider/Position parent resolution, preserving last-known PositionID.
- Verify owned provider cleanup before optional API cleanup; projection-disabled
  deletion warns about residual external positions without calling the API.
- Document direct-installation migration and qualify standalone hierarchy, connected
  failures and idempotent retries against real Kubernetes and HTTPS Keycloak.
- Align current chart, image and release/rehearsal metadata to 0.2.0.

- Introduce versioned internal IAM intent, resolved references, capability evidence
  and locally compiled execution plans for resource-server authorization and realm roles.
- Separate canonical intent and provider-plan identities; reject stale local inputs
  and unsupported/lossy desired semantics before provider mutation.
- Replace the untrusted authorization-plan annotation with a locally computed
  successful Manage identity; keep Observe evidence read-only.
- Require explicit UID ownership for HankoRole management/deletion, preserve native
  metadata and additive composites, and qualify both adapters with shared real
  Keycloak fixtures. Early unmarked roles require administrator-reviewed adoption.
- Bound domain error/evidence rendering, compare full permission bindings without
  expanding grants, preserve foreign objects during authorization cleanup, and document portable/native API boundaries.
- Qualify installed role contracts against their current Synced status and permit
  namespaced current-API Event recording with only create/patch authority.

- Expose bounded intent/evaluated/applied/observation evidence for HankoRole and
  HankoResourceServer; distinguish successful reads, drift, incomplete coverage and stale plans.
- Require acceptable provider read-back before advancing applied generation/hash;
  recover lost status writes through UID ownership and bounded authorization checkpoints.
- Observe the complete supported authorization graph and direct additive realm-role
  membership; preserve read-only native findings without exporting provider data.
- Read every bounded Keycloak authorization collection page before comparison or
  cleanup; reject incomplete reads and preserve native objects beyond the default first page.
- Add a deterministic bounded IAM reporting DTO; defer live Hub transport pending
  receiving-schema qualification. Existing enabled unmarked resource servers require
  administrator-reviewed migration before management.


## 0.1.0 — Source frozen; publication pending

First standalone hankoShell Operator distribution, licensed under Apache-2.0.

### Release overview

hankoShell Operator 0.1.0 reconciles declarative Keycloak IAM configuration from
Kubernetes. Application login clients, redirect URLs, token claims, roles and
machine identities can be reviewed alongside deployment manifests. Reconciliation
updates the supported fields/resources under the operator's ownership; observation
and import allow administrators to review existing configuration before adoption.
Hub, hankoShell API and Continuum fleet integrations are optional for this use case.
Project: https://hanko.sh.

Capabilities include realms, reusable IAM/MFA policies, application and client
roles, identity providers/mappers, resource-server configuration, service accounts
and client-secret rotation. Keycloak still performs login, token issuance and
authentication email delivery. The operator is not a general user-provisioning tool.

Qualification covers Linux Kubernetes **1.35–1.37**, using API-server/etcd fixtures
**1.35.0, 1.36.2 and 1.37.0** for all 16 CRDs, server-side apply, RBAC and Restricted
admission. Real HTTPS Keycloak Admin API v1 tests cover **26.8.0 and 26.7.5**,
including reconciliation, least-privilege identities, denied operations and
ownership/finalizers. Other Keycloak patches/major lines and Kubernetes minors
are unqualified. This is not cloud, node, CNI/CSI, browser-login or production
database qualification.
An installed-system test combines Helm, the scanned operator OCI image, kind
Kubernetes **1.37.0** and HTTPS Keycloak **26.8.0**, including manager restart,
drift repair, namespace RBAC and finalizer deletion. Its single-node/dev-file
fixture does not qualify NetworkPolicy enforcement or production recovery.

Administrative transport requires verified HTTPS by default. Intentionally
trusted HTTP requires an explicit standard-profile acknowledgement; enterprise
remains HTTPS-only. Use a dedicated credential with the documented target-realm
permissions, namespace-scoped RBAC, non-root Restricted pod settings and explicit
default-deny networking. Credentials stay in referenced Secrets. Metrics are
disabled by default; enabled metrics use plaintext HTTP with constrained ingress.
Hub bundles use token-derived HMAC, not an independent publisher signature.
Mesh policy projection is audit-only, not workload enforcement.
Hub self-updates require a local digest/version/source approval and verified
publisher signature. Decommission authorization expires at its deadline.
Instance master hardening, administrative credential rotation and adopted
Service discovery writes require explicit spec opt-ins.
Managed instances require an explicit serving TLS Secret and expose native
HTTPS/8443. HTTP requires both process and instance acknowledgements in standard
profile; enterprise rejects it. Optimized images must include root-context health
endpoints; the separate HTTP/9000 health listener has no Service or pod ingress.
Database snapshots require an explicitly approved and publisher-verified image
digest plus a dedicated backup Secret; the Job receives only selected libpq keys.
Backup images need their own security review and database recovery qualification.

Install the reviewed source chart, or the published
`oci://ghcr.io/alien6-studio/charts/hankoshell-operator` chart at version `0.1.0`
when available, following the [secure deployment guide](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/secure-deployment.md)
and [permission model](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/keycloak-permissions.md).
Published chart values select the scanned multi-architecture image digest.
Publication requires a GitHub-verified source commit and a GitHub-verified signed
annotated SemVer tag bound to that exact commit on protected main. Sigstore
signatures and Continuum Attest verification remain separately mandatory.
Source govulncheck and final-image scans (including embedded cosign) are additive;
fixable HIGH/CRITICAL findings block delivery. BuildKit SBOM/provenance, Sigstore
signatures and signed/timestamped Continuum Attest delivery bindings have distinct
purposes; none guarantees absence of vulnerabilities.

**0.1.0 is a normal SemVer release in initial development, not a prerelease.**
The `hanko.sh/v1alpha1` APIs are experimental and may change across minor versions
before 1.0. `HankoOperation`'s `Upgrade`, `Clone` and `DBSwitch` workflows are
experimental; their completion, interruption/retry and recovery are unqualified.
Future qualification has no scheduled release version. Portable backup/restore
is not qualified; snapshots, clones and database-reference switches are not a tested
disaster-recovery path. Rolling back
the operator does not undo provider deletion, credential rotation or CRD changes.
Deployment-specific image admission, database recovery and enterprise integration
require administrator qualification. Report vulnerabilities privately through
[GitHub security advisories](https://github.com/Alien6-Studio/hankoshell-operator/security/advisories/new);
response targets and supported versions are in SECURITY.md.

### Added

- Release eligibility requires a GitHub-verified source commit and a
  GitHub-verified signed annotated SemVer tag bound to that exact commit on
  protected main. Missing/unverified signatures, lightweight tags and moved or
  conflicting references fail closed. Bounded Git metadata avoids the complete
  root diff while retaining the 1 MiB response limit. Artifact authentication
  remains separately required through Sigstore and Continuum Attest.

- Required installed-system qualification combining the chart, scanned OCI image,
  real Kubernetes and HTTPS Keycloak with a target-realm service account.
- Native OCI/Helm publication rehearsal with interruption after every external
  publication write, checkpoint restore, content conflicts and read-only retries
  against matching drafts/published releases; GitHub storage remains a fixture.

- Shared release packaging contract and a required nonpublishing rehearsal using
  the exact scanned OCI archive, curated notes, checksums, local cosign signature
  and native signed/timestamped/recomputed Continuum Attest fixture evidence.
  Production signer/TSA, GitHub OIDC, registry publication and Artifact Hub
  ownership remain separate launch requirements.
- Align documentation, CRD descriptions and catalog metadata with normal 0.1.0
  initial-development releases and experimental v1alpha1 APIs. Explain lifecycle
  and privileged-operation limits; replace the misleading Helm signKey annotation
  with an explicitly named Attest delivery verification-key link.
- Honor the existing `leaderElect: false` chart setting by passing an explicit
  boolean manager flag; default election remains enabled. Reject non-boolean values.

- Tested Keycloak administrative permission contract for existing realms, optional
  features and read-only import/observation, with required positive and denied
  operations on real 26.8.0/26.7.5 service accounts and a complete API inventory.
  Record version-dependent server disclosure and 26.7.5 view-client secret access.

- Required real-Keycloak HTTPS Admin API qualification on digest-pinned 26.8.0
  and 26.7.5: lifecycle, IAM/MFA policy, roles, brokers, credential rotation,
  drift, ownership/finalizers and read-only import. Document exact qualification
  limits and scoped administration requirements; preserve existing API/versions.
- Declarative Keycloak realms, applications, roles, reusable IAM profiles,
  service accounts and resource servers using the existing `hanko.sh/v1alpha1` API.
- External, managed and adopted provider modes; the official Keycloak operator
  remains optional.
- Optional hankoShell API organization projection, supervision and Hub fleet
  enrollment, synchronization and credential rotation.
- Standard and enterprise installation profiles, private Continuum Hub
  transport, baseline NetworkPolicy and optional Cilium policies.
- Helm packaging, Linux AMD64/ARM64 image builds, Sigstore signing and
  mandatory Continuum Attest delivery verification in the release workflow.
- Artifact Hub chart annotations, icon and OCI repository metadata publication.
- Security policy, code of conduct and secure deployment/trust documentation.

### Security

- Commit a verified delivery checkpoint before release promotion. Retries reuse
  its exact image/chart/signatures/Attest bytes, rescan the committed image under
  the current policy and verify native trust again. Reuse matching packages and
  draft assets; fail on conflicting digests/content instead of overwriting.
  Recover only expected zero-byte failed-upload placeholders in matching drafts;
  never delete or replace complete/nonempty assets or mutate published releases.

- Bound every Keycloak HTTP response in the reviewed permission gateway: 1 MiB
  Admin representations, 64 KiB tokens/client secrets and 8 KiB non-2xx responses.
  Check actual decompressed bytes, close network bodies, reject overflow and
  incomplete streams before exposing data or accepting write acknowledgements.
  Require complete token/rotated-secret JSON; test every reviewed route/method,
  exact boundaries, inaccurate length headers, gzip expansion and broken streams.

- Remove the mutable default database snapshot image and broad DB Secret import.
  Require an explicit `backupImage` digest/source/publisher approval scoped to
  `database-backup`, live signature verification and a separate `backupSecretRef`.
  Recheck approval/key revocation after all workload signature checks. Harden
  backup pods with read-only root, RuntimeDefault seccomp and no Kubernetes token;
  reject foreign/legacy/altered Jobs instead of trusting their name or completion.
  Qualify schema, real Kubernetes Job round-trip and Restricted pod admission.

- Make metrics disabled by default across the binary and Helm listener, port,
  Service, discovery and ingress. Separate optional ServiceMonitor discovery,
  require exact Prometheus namespace/pod selectors with baseline NetworkPolicy,
  and admit only their conjunction on TCP/8080. Reject invalid/broad configuration
  and verify the contract with Helm, controller-runtime and real Kubernetes APIs.

- Require a checksum-pinned Trivy gate on both final OCI runtime platforms,
  including cosign's versioned main module, dependencies, Go runtime and OS
  inventory. Block fixable HIGH/CRITICAL vulnerabilities and validate scoped,
  expiring HIGH exceptions; retain complete reports and fresh database identity.
- Build/export once, verify and copy the scanned OCI graph without rebuilding;
  defer the release image tag until signatures and Continuum Attest verification
  pass. Pin the scanned digest in the delivered chart and bind reports/policy
  in signed checksums and the receipt.
- Build cosign as a versioned dependency for scanner visibility and update its
  crypto dependency to v0.56.0 after image scanning identified fixable findings.

- Require verified HTTPS by default for administrative Keycloak connections,
  including instance, tenant and rotation paths. Require explicit standard-only
  HTTP acknowledgement, retain HTTPS-only enterprise, validate endpoint forms
  consistently in Helm/Go and keep certificate verification enabled.

- Remove operator self-grants of master proxy roles, including impersonation;
  require administrator-provisioned target access and let Keycloak own proxy
  lifecycle. Verify the three-role common profile without global administrator
  privileges; document native creator grants and optional master authority.
- Reject unreviewed Keycloak HTTP methods/routes at a common permission gateway;
  refuse redirects, require inventory updates and reject network-call bypasses
  in regression tests.

- Qualify Kubernetes 1.35–1.37 with real API-server/etcd tests of all 16 CRDs,
  server-side apply, CEL, status, RBAC and Restricted admission. Require every
  matrix result before merge or Attest delivery; reject unqualified cluster minors.
- Schedule the operator on Linux nodes and add optional RuntimeDefault AppArmor
  and stable user namespaces (>=1.36), preserving the mandatory baseline.
- Bound Hub bundle and mesh-policy responses to 1 MiB, control responses to
  64 KiB, and error responses to 8 KiB; propagate body-read errors and discard
  partially decoded heartbeat commands.
- Enforce verified TLS 1.3 and reviewed destinations in the enterprise profile,
  with controlled public bootstrap and no implicit public synchronization fallback.
- Keep signing and policy-administration privileges outside the operator;
  require reviewed admission controls for workload-image policy changes.
- Install and verify the pinned golangci-lint v2.14.0 independently of the PATH.

### Fixed

- Align managed Keycloak listener, serving certificate, Service, probes and
  ingress policy with the HTTPS administrative transport contract. Validate TLS
  configuration before infrastructure changes; refuse implicit HTTP and mismatched
  serving certificates. Use optimized startup with the read-only image filesystem.
  Advertise the validated AdminRef endpoint to API discovery without a scheme
  downgrade or a hostname change.
- Require independent local release approval and publisher verification before
  Hub self-updates, including already-pinned images; reject stale Deployment
  patches after concurrent administrator changes.
- Reject expired/malformed decommission commands and stop further cleanup or
  confirmation when their execution deadline is reached.
- Limit instance administrative writes to explicitly requested master hardening,
  AdminRef rotation and adopted Service discovery. Existing resources default
  to external administration; requested hardening failures cannot report Ready.

- Accept bounded native authorization creation representations when Keycloak
  omits Location, and the successful 201 response to authorization updates.

### Compatibility and limits

- `metrics.enabled` is now the global switch; existing ServiceMonitor users must
  also set `metrics.serviceMonitor.enabled` and configure Prometheus identity and
  discovery labels. Disabled metrics remove the old always-on listener/Service.
  Metrics remain unauthenticated HTTP; NetworkPolicy requires a supporting CNI
  and does not encrypt traffic. Review prior exposure/defaults before rollback.

- Existing HTTP Keycloak values now fail closed unless administrators explicitly
  set `keycloak.allowInsecureHTTP: true`; prefer migrating to verified HTTPS.
  Default chart endpoint/egress changes to HTTPS/8443. Public CA endpoints need
  no CA Secret; private CA configuration remains supported.

- The deprecated `HankoEmailProvider` no longer reads vault credentials or sends
  messages;
  messaging integrations belong to the API and Keycloak retains native SMTP.
- Hub bundles retain HMAC authentication derived from the bearer token, without
  independent publisher authentication. Ed25519 mesh policies use a separate
  trust boundary; their operator projection remains audit-only.
- Backup/restore portability, cloud-specific networking and mesh enforcement
  require installation qualification. Auth0 integration is not implemented.
