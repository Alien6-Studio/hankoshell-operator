# Security qualification workstream (#99)

Status on 2026-10-17: **in progress**, on `feat/1.0.0-dev`. This is the
maintainer's qualification record and test map, not an independent audit or a
stable-contract acceptance. The APIs remain experimental. #77 is closed; stable
versions/conversions (#91) and stored-object migration/rollback (#92) are open.
No merge, release, registry publication or production approval follows from this
record.

## Parser and decision campaign

The reviewed [inventory](../../../scripts/fuzz-targets.json) contains twenty
compiled Go fuzz targets in ten packages. Positive seeds and hostile cases are
checked in with `f.Add`: duplicate/escaped JSON members, trailing documents,
size/depth boundaries, DTD/entities, duplicate XML IDs, private JWK fields,
foreign ownership, stale approvals and mutable/foreign image references. Fleet
seeds use a fixed synthetic signing key so coordinator and worker processes
exercise the same positive corpus. Signed-payload fuzzing deliberately re-signs
mutations to reach validation behind the signature check.

| Surface | Targets and security properties |
| --- | --- |
| Shared JSON | `FuzzJSONDocument`: syntax, trailing values, safe diagnostics; deterministic unit tests enforce duplicate/depth/member bounds |
| Protocol discovery | `FuzzOIDCDiscovery`, `FuzzPublicDiscovery`, `FuzzPublicKeys`: bounded documents, exact issuer/endpoints, closed public-key evidence; private key injection refused |
| SAML metadata | `FuzzSAMLMetadata`: bounded XML, issuer/SSO binding, namespaces/certificate decoding, no DTD/entities or extra roots; positive certificate generated locally |
| Signed fleet state | `FuzzFleetEnvelope`, `FuzzFleetSignedPayload`, `FuzzFleetTrust`: signature tampering, target binding, exact recovery identity and lower-sequence replay refusal after successful verification |
| Acquisition | `FuzzAdoptionReceipt`, `FuzzAdoptionApproval`, `FuzzAuthorizationJournal`: canonical receipt, exact owner/client, conflicting approval channels, bounded native ownership inventory |
| Recovery and transitions | `FuzzTrustRecoveryMetadata`, `FuzzAuthenticationJournal`, `FuzzAuthenticationApproval`, `FuzzDeliveryRecord`: canonical journals/checkpoints/approvals, immutable identity and absent-vs-invalid distinctions |
| Hub wire | `FuzzLegacyBundle`, `FuzzHubControlResponse`: independent byte/object budgets, unambiguous commands/credentials and no trailing values |
| Image authority | `FuzzImageReference`, `FuzzImageApprovalPolicy`: registry/repository boundaries, immutable SHA256 identity and qualified publisher approval |
| Provider status | `FuzzProviderStatusDecision`: arbitrary error text cannot impersonate 403/404; wrapping native text around a typed error cannot change its numeric status |

`make security-fuzz` runs every compiled target for 15 seconds with two workers.
`FUZZ_SECONDS=60 FUZZ_OUTPUT=/tmp/hanko-fuzz make security-fuzz` extends a local
campaign. The runner refuses missing/extra targets, skipped/failed campaigns,
zero mutation executions, incomplete baseline coverage, timeouts, output overflow
and source changes. Every Go failure blocks the gate, including panic, crash and
runtime allocation failure. The default report is
`.tools/security-fuzz/results.json`; raw JSON events, stderr, minimized failures
and interesting cache entries are retained beside it. `dirty: true` identifies
local development evidence and cannot be treated as an exact clean-commit result.
Reproduce a saved failure with
`go test ./internal/PACKAGE -run='FuzzNAME/HASH'` after copying it into that
target's `testdata/fuzz/FuzzNAME` directory.

The full CI aggregate requires the fuzz job, which also runs on development
pushes. Existing CodeQL, gosec/lint, govulncheck, mutation, OCI, real-API/provider,
installed-system and release-rehearsal gates remain in place. Four new mutation
cases prove that removing each added JSON ambiguity guard causes a completed
test failure. A finite campaign cannot prove absence of defects or unbounded
allocation. `GOMEMLIMIT=256MiB` is a **soft** Go runtime target, not an OS memory
limit or allocation measurement. The worker, wall-time and output bounds limit
execution; allocation profiling and longer campaigns remain review work.

## Threat model checkpoint

| Boundary / actor | Required authority | Evidence and remaining review |
| --- | --- | --- |
| Remote Hub or publisher | Locally approved issuer/key/source, exact tenant/cluster/namespace and monotonic durable checkpoint | #77 verification/replay tests, signed-payload fuzzing; rerun installed adversarial matrix on final stable version |
| Provider-controlled documents | Trusted TLS origin, bounded complete response, closed identity/journal evidence; numeric typed status only | Protocol/JSON/ownership fuzzing and existing transport tests; collection allocation analysis remains |
| Namespace object writers | Current CR UID/generation, administrator approvals where required, exact live target identity and optimistic writes | Ownership/authority tests, admission tests and 68 security mutations; stable CRD field inventory and full RBAC verb table remain |
| Application credential delivery | Matching controller owner plus fresh provider value, consent/current target UID, resource-version writes and read-back | Canonical/projection race tests; legacy migration now exercises explicit administrator Secret binding |
| Image policy administrators | Approved digest, purpose, source revision and publisher; ambiguity cannot select another approval | Publisher-policy fuzzing plus existing revocation/signature/installed tests; no fuzz test substitutes for a signature verifier |
| API conversion/storage migration | Lossless round trip, preserved journals/approvals and reversible journaled storage movement | Not implemented yet: depends on #91/#92; add conversion and migration fuzzing against that actual implementation |

Namespace administrators, provider administrators, repository/workflow
administrators and local image-policy writers have distinct trust boundaries;
namespace membership alone is not evidence that a writer may approve privileged
operations. The [deployment trust model](../../secure-deployment.md) and
resource-specific contracts remain authoritative. This checkpoint does not grant
new authority or accept unresolved candidate findings.

## Admission and RBAC inventory

The [schema/grant review](../../security-surface.md) now records 962 declared
fields/collections and every rendered RBAC rule/binding on four chart profiles.
Seven reference fields gained explicit length bounds and Kubernetes-name checks;
the common real-API fixture also covers the existing workload-trust reference.
The leader lock loses broad read/renew/delete privileges. Preflight checks the
reviewed inventory. 348 explicit length/cardinality gaps and broad dynamic
Secret/Deployment authority remain contextual review work; inventory is not
acceptance. See the migration notice before applying changed alpha CRDs.

## Remaining acceptance work

- Complete stable API/conversion and stored-object migration first, then fuzz
  their actual wire/storage contracts and qualify interrupted transitions.
- Inventory every public CRD string/list/map bound against the chosen provider
  limits and add missing admission tests; do not infer coverage from parser tests.
- Publish a complete RBAC resource/verb/justification table, including generated
  Secret/Deployment writes, dynamic names and admission protections.
- Run the complete installed ownership/replay/stale-approval/SSA/foreign-tenant
  matrix on the final candidate across the supported Kubernetes/Keycloak cells.
- Finish independent security review with resolved/accepted findings. The earlier
  optional Security CLI audit was interrupted by the service and produced no
  completed verdict; its empty confirmed-findings output is not a clean audit.
- Review longer fuzz campaigns and allocation evidence, plus parsers beyond the
  initial inventory (including runtime application cleanup journals and stable
  conversion parsers as they are added). Keep #99 open until its full acceptance
  criteria are met.
