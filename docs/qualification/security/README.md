# Security qualification workstream (#99)

Status on 2026-10-19: **in progress**, on `feat/1.0.0-dev`. This is the
maintainer's qualification record and test map, not an independent audit or a
stable-contract acceptance. The APIs remain experimental. #77 is closed; the served conversion (#91) and stored migration (#92) contracts are implemented
and their tickets are closed.
No merge, release, registry publication or production approval follows from this
record.

## Parser and decision campaign

Qualification evidence uses `scripts/evidence_privacy.py` for JWT-shaped text.
The scanner consumes complete components once rather than retrying a multi-part
regex at every attacker-controlled header prefix. Small generated-input tests
check compatibility with the old detector; a bounded child process exercises
long dot-free headers and incomplete tokens. Detection and diagnostic redaction
share this implementation, including the copy mounted into the disposable Hub.

The Authentik qualification runner passes database/bootstrap credentials and API
tokens through named child environment variables, with no values in argv or
credential files. The Go fixture reads tokens from its process environment.
Only fixed public connection metadata and validated UUIDs may reach its mode-0600
connection file, created without an initially permissive window. These are test
infrastructure changes; no production operator API or RBAC authority changes.


The reviewed [inventory](../../../scripts/fuzz-targets.json) contains 26
compiled Go fuzz targets in twelve packages. Positive seeds and hostile cases are
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
| SAML metadata | `FuzzSAMLMetadata`, `FuzzSAMLACS`: bounded XML, issuer/SSO binding, namespaces/certificate decoding, no DTD/entities or extra roots; positive certificate generated locally |
| Signed fleet state | `FuzzFleetEnvelope`, `FuzzFleetSignedPayload`, `FuzzFleetTrust`: signature tampering, target binding, exact recovery identity and lower-sequence replay refusal after successful verification |
| Acquisition | `FuzzAdoptionReceipt`, `FuzzAdoptionApproval`, `FuzzAuthorizationJournal`: canonical receipt, exact owner/client, conflicting approval channels, bounded native ownership inventory |
| Recovery and transitions | `FuzzTrustRecoveryMetadata`, `FuzzAuthenticationJournal`, `FuzzAuthenticationApproval`, `FuzzDeliveryRecord`: canonical journals/checkpoints/approvals, immutable identity and absent-vs-invalid distinctions |
| Runtime outputs | `FuzzRuntimeCleanupJournal`, `FuzzRuntimeTargetAuthorization`: canonical bounded cleanup records, exact application/workload/target consent and deletion refusal |
| Delegation recovery | `FuzzBoundedDelegationDocument`, `FuzzBoundedDelegationActorMarker`: native phase/authority bounds, physical client and owner binding, replacement actor UID and sibling-owner refusal |
| API versions | `FuzzAPIVersionRoundTrip`: bounded non-default alpha/beta object conversion, journals and identity preservation; deterministic tests cover all exported fields and lists |
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
| Provider-controlled documents | Trusted TLS origin, bounded complete response, closed identity/journal evidence; numeric typed status only | Protocol/JSON/ownership fuzzing and existing transport tests; byte/depth/member/object limits reviewed; hostile boundary seeds remain mandatory |
| Namespace object writers | Current CR UID/generation, administrator approvals where required, exact live target identity and optimistic writes | Ownership/authority tests, admission tests and 71 reviewed security mutations; complete field fixtures and rendered RBAC/admission inventory |
| Application credential delivery | Matching controller owner plus fresh provider value, consent/current target UID, resource-version writes and read-back | Canonical/projection race tests; legacy migration now exercises explicit administrator Secret binding |
| Image policy administrators | Approved digest, purpose, source revision and publisher; ambiguity cannot select another approval | Publisher-policy fuzzing plus existing revocation/signature/installed tests; no fuzz test substitutes for a signature verifier |
| API conversion/storage migration | Lossless round trip, preserved journals/approvals and reversible journaled storage movement | Experimental alpha/beta conversion fuzzing, real API readers and native storage fixture; no stable/public graduation is implied |

Namespace administrators, provider administrators, repository/workflow
administrators and local image-policy writers have distinct trust boundaries;
namespace membership alone is not evidence that a writer may approve privileged
operations. The [deployment trust model](../../secure-deployment.md) and
resource-specific contracts remain authoritative. This checkpoint does not grant
new authority or accept unresolved candidate findings.

## Admission and RBAC inventory

Runtime application cleanup now requires the exact JSON representation produced
by its own journal writer. A reproduced regression showed duplicate/escaped or
case-aliased fields and ignored unknown fields reaching output PATCHes. The
reader rejects these, null, trailing documents and noncanonical encodings before
any output write, with the fixed `CleanupConflict` reason. Existing 49,152-byte
and 32-record limits remain. Two mutation checks enforce representation and
record bounds. This is defense against ambiguous recovery state; the journal
continues to be a lookup hint, with fresh independent target consent required.

Migration: writer-generated journals remain byte-for-byte compatible. Before
upgrading, review any manually edited journal against the original writer output;
otherwise cleanup/delivery can stop with `CleanupConflict`. Preserve outputs and
the journal for review; do not strip the annotation or finalizers to force
cleanup. Rolling back the image restores the earlier permissive reader, so
review the retained journal before resuming destructive cleanup on that image.
No CRD, stored version, provider state or existing journal is rewritten.

The native shared-actor reader now decodes existing markers into an empty value.
It previously overlaid the caller's initialization marker, allowing missing,
partial or null version/actor fields to inherit the requested identity. The
regression reproduces all five cases. Existing markers must now explicitly
provide their own valid version, complete actor binding and nonempty owner map;
the stored exchange history remains authoritative. Absent markers retain the
fresh-initialization path. A mutation check restores the old overlay and must be
detected. Valid writer-generated markers are unchanged; malformed markers stop
with ownership conflict and must be reviewed before retrying or rolling back.

The [schema/grant review](../../security-surface.md) records 1,343 served
string/list/map paths with no missing maximum, six complete RBAC/admission
profiles and configuration/upgrade instructions. The independent field corpus
covers all 966 alpha paths and every shared beta path; the maximum-boundary
corpora remain separate. Secret/Deployment writes require exact administrator
names, with mandatory fail-closed admission for creations and token/RBAC
escalation guards. The leader lock retains only named read/renew and namespace
CREATE required by client-go.

The completion audit is an **internal instrumented source/configuration review**,
with explicit findings, fixes and reproducible evidence. It is not an external
penetration test or independent human signoff. The earlier optional Security CLI
run was interrupted and produced no completed verdict; an empty confirmed-finding
list is not used as a clean audit result. #99 asks for an external review **or an
audit report**; this record uses the audit-report route without claiming a
stable API, production qualification or first publication.

The [completion audit](2026-10-19/bounded-contract/README.md) records the findings,
fixes, trust assumptions and final integration gate.

## Completion gate

Retain the current source tests, complete parser campaign, mutation results,
real-API field/admission tests and actual operator-token probe. Attach the
required CI, CodeQL, OCI, rehearsal and installed ownership/replay/stale-approval/
SSA/foreign-tenant results for the exact protected integration candidate. Resolve
any finding or failure before recording the final decision. A passing earlier
image is diagnostic context and cannot qualify changed source. The final report
will link its immutable candidate and evidence; no tag/release/publication is
part of this task.
