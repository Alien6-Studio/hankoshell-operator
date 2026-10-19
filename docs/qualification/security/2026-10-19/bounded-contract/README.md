# Public contract security audit — #99

Internal instrumented source/configuration audit of the unpublished development
contract, performed with Codex. This is the audit-report route in
[#99](https://github.com/Alien6-Studio/hankoshell-operator/issues/99), not an external
penetration test or independent human attestation. No stable graduation,
production approval, tag, release or registry publication is authorized by it.

The review covers all 17 resources / 20 served schemas, alpha/beta conversion,
protocol and recovery parsers, typed provider failures, ownership/approval/
replay transitions, rendered Kubernetes authority and installed adversarial
fixtures. Keycloak itself and Hub/Continuum internals are outside this audit.

## Findings and disposition

| Finding | Resolution and executable evidence |
| --- | --- |
| Public input/status collections and imported fields lacked explicit budgets | Resolved: generation policies and Go markers preserve existing stricter constraints; the inventory rejects missing maxima. All 966 alpha paths / 1,343 served paths have independent admission fixtures; 95 input and 232 status cases additionally check accepted maxima. |
| Declared description/redirect/role-attribute budgets exceeded native storage columns | Resolved: eight paths align with the unchanged VARCHAR/NVARCHAR(255) definitions in both qualified Keycloak tags. Compilers reject oversized values before I/O; SAML ACS parsing checks length first. Native tests accept maximum Unicode descriptions and retain larger NCLOB/CLOB metadata. See [source identities and mappings](native-storage-limits.json). |
| SAML ACS accepted some escaped control bytes or invalid decoded UTF-8 | Resolved: validate the decoded path as UTF-8, reject all C0/DEL and escaped wildcard/backslash while preserving encoded spaces and legal Unicode. Unit regressions and the dedicated ACS fuzz target cover the normalization boundary before any provider I/O. |
| Partial realm broker replacement could lose old mapper cleanup identities | Resolved: retain old/new `(name,keycloakID)` checkpoints until cleanup acknowledgement; reserve previous plus desired inventory before provider writes. Real API migration retains old SSA ownership without force. Identifiers are never truncated. |
| Dynamic Secret/Deployment authority could reach unrelated targets | Resolved: administrator-configured exact namespace/name targets; named update/patch RBAC; mandatory fail-closed CREATE/UPDATE/DELETE admission. Forged ownership/labels do not extend targets. Projection CREATE requires separate approval. |
| An approved Secret name could be used for a legacy ServiceAccount token | Resolved: writes allow only Opaque credentials and refuse service-account token annotations/types. Positive ordinary outputs and hostile native-valid inputs run under actual admission. |
| Metadata-adoption permissions could delegate authority or alter ClusterRole aggregation | Resolved: mandatory admission preserves rules, subjects, role references, aggregation rules/labels, annotations and finalizers. Owner-reference-only adoption remains available for decommission. Tests add an already-held permission and another subject, avoiding native escalation rejection as a false positive. |
| Provider Deployments or dynamic Jobs could select another Kubernetes identity | Resolved: current Restricted namespace admission is mandatory for these writes. Provider account bindings cannot change; new providers and Jobs use default/no account, explicitly disable automount and reject projected API tokens. Jobs cannot bypass the sensitive-write boundary through another ServiceAccount. |
| Valid Keycloak client IDs could yield invalid Kubernetes Secret names | Resolved: preserve every previously valid complete name; otherwise use a separate dot-prefixed namespace and full SHA-256 of the exact UTF-8 client ID. Independent vectors cover Unicode, URNs, length and collision separation. Delivery reads the hashed source and refuses self-projection. |

No new finding above is left for risk acceptance. The deployment's existing
trust assumptions remain explicit: the API server/cluster administrator and
configured providers are trusted; watched CR authors can influence operations
within granted authority. The operator namespace is not a boundary for mutually
hostile tenants. Credential reads are uncached namespace-local get; a compromised
manager can exercise the union of loaded Kubernetes/provider credentials.
Keycloak 26.7.5's dependent-reader native client-secret exposure remains documented
in the [provider contract](../../../../keycloak-permissions.md). This audit does
not grant an exception, conceal that exposure or promote the experimental
feature to stable. Separate production/publication decisions remain separate.

## Parser, failure and allocation review

The [compiled fuzz inventory](../../../../../scripts/fuzz-targets.json) includes
26 targets in 12 packages: JSON, OIDC/SAML, public discovery/JWKs, signed plans,
Hub responses, ownership and authentication journals/approvals, runtime output
records, bounded delegation, image references/policies and alpha/beta conversion.
The campaign executes its positive/hostile seeds before mutation. HTTP/document
callers bound bytes before decoding; shared JSON rejects depth above 32,
duplicate members, more than 1,024 object members and trailing values. Signed
Fleet content also limits total objects to 200. XML rejects DTD/entities and
ambiguous roots/IDs; JWK and journal readers validate closed identity/size
contracts. Boundary seeds exercise these limits. Fuzzing is finite and the Go
memory setting is a soft runtime target, not a formal memory or vulnerability
proof. No crash, panic or unbounded-allocation finding is accepted as a passing
campaign.

Provider HTTP status is carried by numeric `keycloak.StatusError` and inspected
through `errors.As`; prerequisite failures use typed/sentinel errors. Conditions
select bounded reasons through typed decisions. Remote diagnostics, strings that
say "403"/"404", and wrapped attacker text cannot impersonate authority.
The provider-status fuzz target and typed diagnostic tests cover this boundary.
Ordinary validated identity/configuration strings retain their intended semantic
role; free-form descriptions are not forced into Kubernetes-name patterns.

The retained [fuzz campaign](security-fuzz.json) and
[mutation campaign](security-mutations.json) record completed executions and
unmutated baselines. The final integration reruns both on its exact source.

## Authority and migration

The [complete resource/verb table](../../../../security-surface.md) and
[machine inventory](../../../../security-surface.json) cover six administrator
profiles and freeze the full admission specs/bindings, including seven mandatory
sensitive-write, delegation and Job policies. Source checks reject wildcard,
impersonation/bind/escalate, runtime token issuance/review/exec and unnamed
Secret/Deployment update grants. Kubernetes cannot name-scope CREATE; actual
admission must independently reject unrelated targets even with broader RBAC.

Read the [configuration and migration procedure](../../../../secure-deployment.md#exact-secret-and-deployment-write-authority)
before upgrading. Administrator approval of exact output names does not replace
consumer UID consent, native ownership, current intent or optimistic writes.
Do not erase journals/finalizers, truncate identities, force another field
manager, or delete/recreate CRDs to satisfy a bound. Rolling back to broad-write
charts or permissive old readers removes the corresponding protections.

The [local validation manifest](validation.json) records component/report hashes
and executed counts; the final CI remains the authority for the integrated image.

## Qualification and final decision

The completed local campaign passed 2,840 Go race tests, 4,861 API checks on
each of three Kubernetes versions (14,583 total), all coverage floors and 454
Python tests. All 26 fuzz targets passed 5,990,404 executions; all 71 security
mutations were detected against passing baselines. Native storage scenarios
passed on both qualified Keycloak versions. Raw campaign identities and report
hashes remain in the validation manifest; these are local source results.

Local reports identify the tested parent revision and dirty development tree;
they do not claim that an older scanned image contains new Go source. The [completed baseline upgrade](installed-baseline-upgrade.json) and
retained operational smoke uses the existing scanned `d1afbd4` image with the
new chart/harness and proves actual token-only admission, two Restricted
replicas, mTLS and leader replacement. It qualifies that harness/configuration
and the compatible upgrade surface, not the new compiled candidate. No private
token, Secret body or administrator kubeconfig is published.

The installed upgrade also checks late administrator-prepared projection grants:
the Role/RoleBinding explicitly retain Helm release ownership so the subsequent
real upgrade can adopt them. A first full-system attempt exposed missing release
metadata; that failed attempt is excluded from passing qualification.

The final protected integration must rerun every required source, CodeQL,
Go/race, three-version API/native migration, provider/extension, parser fuzz,
security mutation, OCI, rehearsal and installed system/workload/delegation/
portable/Fleet/HA gate on its exact scanned image. Installed tests include
ownership races, replay/tamper, stale approvals, SSA conflict, foreign tenants
and actual operator-token refusals. A passing earlier integration is context,
not a substitute. The issue's final **Resolution** must bind the published report,
exact passing integration run and **Verified protected squash commit**. Until
those results exist, this report records resolved source findings and does not
claim final acceptance.
