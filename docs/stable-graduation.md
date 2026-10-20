# Resource graduation criteria for 1.0

Decision for #90, reviewed on 2026-10-16. These criteria and per-resource records
are inputs to #89/#104, not their acceptance or a stable API announcement. No
public release or production compatibility report exists. **No resource
graduates in this decision.** The initial 1.0.0 public candidates remain a
separate prospective selection, not evidence of 1.0 maturity.

The machine-readable [graduation records](../tools/qualification/config/contracts/stable-graduation.json) cover every
top-level spec/status group of all 17 installed resources, including explicit
native boundaries. Each record names its proposed 1.0 disposition, evidence,
measurable criteria and unresolved blockers. A group includes nested fields;
existing [public selection exclusions](../tools/qualification/config/contracts/public-contract-selection.json) remain.
The current development APIs remain experimental. All records retain `v1alpha1`; this decision adds no conversion/storage version.

| Criterion | Minimum required before a resource may graduate | Evidence location |
| --- | --- | --- |
| Conformance | Every applicable frozen fixture passes; zero unaccepted lossy outcomes. Unsupported outcomes stay explicit. | Shared corpus, source/API/JUnit and provider review |
| Installed | Every supported Kubernetes/Keycloak cell passes applicable scenarios on the candidate or a documented unchanged surface. | Exact-commit, exact-digest installed reports |
| Production | Two independent installations, two public operator releases and one real upgrade/rollback path using the resource. | Sanitized #88 reports; none received |
| Ownership | Zero unexpected foreign writes; recreation, cleanup, replay, interruption and concurrent-writer negatives pass. | Native ownership/adoption and installed recovery suites |
| Compatibility | Lossless served-version round trips and upgrade/rollback from every supported public predecessor; pending transactions preserved or refused explicitly. | #91–#93 captured release fixtures and migration reports |
| Security | Zero open Critical/High findings; accepted findings reviewed; stable-surface review ≤90 days old. | #99 review, fuzzing, adversarial/CodeQL gates |
| Operations | Every published installation/recovery/rollback command references a passing fixture or is explicitly unqualified. | #103 runbooks and fixture links |
| Decision | Zero graduation blockers; community review and explicit #89/#104 acceptance. | Linked issue decisions, not synthetic approval |

Thresholds apply per resource. A provider-wide passing test cannot fill a missing
resource scenario. Evidence may span several reports but must name versions,
commit/digest, scenario, result and limitations. Production reports use anonymous
installation references; omit credentials, tenant data and personal identifiers.
Two fixtures or two clusters run by one test harness are not two independent
production installations. An empty production evidence list prevents graduation.
Use the [reporting and privacy review procedure](production-evidence.md), the
public issue form and the reviewed per-release registry for #88. Its generated
summaries retain open incidents and missing observations; they do not waive any
resource-specific threshold or automatically prove installation independence.

| Resource group | Current graduation record | Additional resource-specific evidence required |
| --- | --- | --- |
| HankoApplication | staying alpha | OIDC registration vs runtime credentials, rotation/projections, native SAML/extensions, Observe/Manage and adoption/cleanup per selected field group |
| HankoRole | staying alpha | Additive realm roles/composites, cycles, foreign assignments and owned cleanup |
| HankoResourceServer | staying alpha | Complete resource/scope/principal graph, explanation bounds, cleanup, organization and unsupported delegation boundaries |
| HankoRealm, HankoIAMProfile | staying alpha | Inherited policy, security revision/defaults, native brokers, owned vs imported realm deletion |
| HankoOrganization | staying alpha | Native organization/group/role hierarchy, ancestor changes and foreign membership preservation |
| HankoServiceAccount, HankoWorkloadTrust | staying alpha | Authentication transitions, secret/workload authority, source UID/CA/issuer binding, age/replay, refusal and recovery |
| HankoIssuer | staying alpha | Current routing observation and host changes; no implicit certificate/ingress rollback |
| HankoKeycloakInstance, HankoImport, HankoTheme | experimental | Infrastructure owner checks, native read coverage, image/Secret/PVC authority, interruption and upgrade rollback |
| HankoOperation, HankoSnapshot | experimental, excluded from stable 1.0 | [ADR-011](architecture/decisions/ADR-011-experimental-lifecycle-authority.md); each future lifecycle action needs independent authority and installed evidence |
| HankoTenant, HankoMeshService | experimental | Public connected authority and upgrade/rollback; installed Fleet evidence does not qualify a public Hub service or traffic enforcement |
| HankoEmailProvider | experimental, deprecated no-delivery API | Explicit retirement path preserving readers; no resumed messaging adapter |

No open security or missing rollback/production evidence may be waived by marking
a resource stable in the table. A future graduation PR must update evidence,
version/migration fixtures and the review gate together, resolve blockers and
record the community decision. #104 reuses these criteria; changing a threshold
requires an explicit RFC amendment explaining its evidence and consequences.

`python3 -m tools.qualification.checks.stable_contract` rejects missing resources/field groups,
undeclared native boundaries, unsupported portability, maturity inflation,
missing evidence, and changes to the frozen shared semantics without review.
The gate runs in preflight and release packaging. It does not invent historical
releases or replace #94's future public-release schema/deprecation gate.
