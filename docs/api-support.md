# API support and qualification inventory

This is the current development inventory for #82, #83 and #85. It does not
ratify the initial public surface selected by #81 or close its prerequisites.
No public release has been published. All planned capabilities remain in the
backlog; an experimental classification is not removal from the roadmap.

The separate [candidate selection](public-contract-selection.md) reviews all
resource/field groups for #81. Its [frozen semantics and corpus](public-contract-semantics.md)
feed #82/#84 qualification; they do not change the current development maturity
table or authorize first publication.

The reviewed [machine-readable inventory](api-support.json) lists every top-level
spec/status field group for every CRD, plus explicit provider-native spec groups.
Each classification applies to all nested fields in that group. Native groups
remain Keycloak extensions: a typed field does not imply provider portability.
Secret references remain references, never evidence of permission to read or
publish their contents. Observed state, Conditions and plan hashes are evidence,
not authorization, transactional completion or a compatibility guarantee.

<!-- api-support:start -->
All 17 `hanko.sh/v1alpha1` resources are experimental; no public API compatibility commitment has been selected.

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

## Evidence and limits

- Realm, profile, role and resource-server semantics use the
  [IAM contract engine](architecture/iam-contract-engine.md). Its unit, API and
  HTTPS provider fixtures qualify the named mappings, not every native field or
  a future stable schema.
- Application OIDC/SAML, native mapper boundaries and runtime outputs follow the
  [application identity contract](architecture/application-identity.md).
- Organizations and structural grant provenance follow the
  [organizational authorization contract](architecture/organizational-authorization.md).
- Service accounts and workload trust retain the exact credential, issuer,
  lifetime and version boundaries in the [permission inventory](keycloak-permissions.md)
  and [installed qualification](secure-deployment.md). They do not imply arbitrary
  provider versions or fleet-wide support.
- Instance management, issuer publication, import, theme builds, configuration
  snapshots and operations retain their individual
  [operational limitations](secure-deployment.md#privileged-lifecycle-behavior-and-limits).
  The installed lifecycle evidence is the same-namespace, external-source,
  configuration-only Clone alias on Kubernetes 1.37.0 / HTTPS Keycloak 26.8.0.
  Upgrade, DBSwitch, managed-source Clone and portable database restore remain
  unqualified as installed provider workflows.
- Tenant/Hub and mesh resources are connected surfaces outside the standalone IAM
  core. Mesh registration is audit/projection, not traffic enforcement.
  `HankoEmailProvider` is retained as a deprecated API; its controller does not
  provide email delivery.
- Delegation accepts typed intent and returns unsupported capability findings;
  [native counterexamples](architecture/delegation-and-agent-identity.md) prevent
  enabling bounded delegation on either reviewed Keycloak version. The second
  provider and signed, replay-resistant enterprise fleet remain separate work.

These are fixture and installed-test boundaries, not evidence of public production
use. The inventory links each resource to its enforcing contract or limitation.

## Change communication

Experimental APIs can change between development revisions and future minor
releases; no backward-compatibility promise has been selected. Schema, default,
ownership, approval, journal or deletion changes still require reviewed migration
and rollback notes in the same change. A classification does not waive those
engineering requirements. The [migration policy](api-migration-policy.md) records
the stored-version and rollback boundaries.

Update the inventory and curated CHANGELOG when a field group or classification
changes. `scripts/api-support.py` and `scripts/release-contract.py` reject missing
resources, unreviewed spec/status groups, missing evidence references and divergent
README/chart/release-note classifications. These checks run in preflight through
the release contract tests; they do not replace conformance or migration fixtures.

#81 must separately select the public field groups using completed capability
evidence and real use. #82 still owns canonicalization/default/ownership goldens;
#84 owns reusable cross-version and installed rollback fixtures. This inventory
does not manufacture a predecessor release or certify downgrade compatibility.

The [1.0 graduation criteria and per-resource records](stable-graduation.md)
and [second-provider contract review](stable-provider-review.md) remain
unratified development inputs. Lifecycle APIs are excluded from the stable 1.0
contract and disabled by default; see [ADR-050](architecture/decisions/ADR-050-experimental-lifecycle-authority.md).
