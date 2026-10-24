# ADR-009: Full qualification matrix on pull requests

Status: Accepted

## Context

The operator supports several Kubernetes and Keycloak versions. A passing test
on one pair does not establish compatibility on the other supported pairs.
Repeating the complete matrix on PR, main and release adds cost without changing
the reviewed source. A squash merge does change the commit identity and image provenance.

## Decision

Every PR, including documentation and dependency updates, runs the complete
supported matrix before protected merge. Scheduled and explicitly requested CI
retain that complete profile.

After merge, main runs a lightweight integration gate. It verifies the signed
commit and the successful PR's immutable source proof against the exact Git tree.
The proof records the actual tested merge revision, PR head, workflow run and
attempt. A deliberate complete CI run on the exact integrated revision can renew
expired evidence. Partial, foreign, missing or mismatched proofs cannot pass.

Release qualification reuses that source proof. It builds one final AMD64/ARM64
image, scans it and runs every installed-image matrix cell and the release
rehearsal on its immutable digest. The matching delegation extension is qualified
for those cells. Go/source-only suites are not repeated. Publishing consumes the
same archive without rebuilding; signatures, fresh vulnerability checks and the
protected release approval remain mandatory.

Keep source proofs for 30 days and OCI archives for seven days. Expired evidence
stops the affected path explicitly. On a publication failure, rerun only publish;
do not restart qualification or replace committed versioned content. BuildKit
caching accelerates builds but never serves as qualification evidence.

## Consequences

PR qualification remains complete. Main verifies integration rather than running
another matrix. Release separately qualifies the final image's exact provenance.
Accumulate a coherent development batch before pushing. Investigate test failures;
never automatically replay tests or ambiguous provider writes.

## Enforcement

- [CI profiles and required gate](../../../.github/workflows/ci.yml) declare which
  jobs must succeed or be skipped; an unexpected result fails the gate.
- [Source proof verification](../../../tools/release/release_eligibility.py)
  binds GitHub run/artifact identities, transport hashes and actual tested Git trees.
- [Release contract](../../../tools/qualification/checks/release_contract.py)
  checks profile inventories and permissions. The existing release rehearsal
  exercises proof substitution, failed runs and expired artifacts.
