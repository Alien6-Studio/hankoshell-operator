# First public 0.1.0 readiness and administrator checklist

**Target public release: 0.1.0. Current status: development.** Technical
metadata is `0.1.0-dev.0`, with Artifact Hub prerelease status true. No public
release has been published yet. All implemented IAM and security behavior is
retained; no permission, dependency or functional rollback accompanies this reset.

Phases 1–5 are the implemented foundation. The complete original prelaunch
trajectory, including Workload Identity, Delegation & Agent Identity, Provider
Portability, Fleet Reconciliation and Initial Public Contract Stabilization
(Phases 6–10), is required before the first 0.1.0. See the [roadmap](../ROADMAP.md).
The 16 `v1alpha1` APIs may remain alpha with explicit initial-public contract and
migration limits. A true later 1.0 decision depends on actual public use and a
proven backward-compatibility policy; there is no predetermined 1.0 milestone.

[#54](https://github.com/Alien6-Studio/hankoshell-operator/pull/54) merged as
`7e0063704738ef9e63968b79d9e553555c2f2eb0` and its canonical Attest hardening is
retained. [#21](https://github.com/Alien6-Studio/hankoshell-operator/issues/21)
remains open for transversal first-publication trust/readiness and Phase 10.
Source qualification and fixture trust do not supply that external evidence.

## Version and publication contract

| Context | Development now | Future first public release |
| --- | --- | --- |
| Operator/chart/app/image/evidence metadata | 0.1.0-dev.0 | 0.1.0 |
| Artifact Hub prerelease | true | false |
| Source release tag | none created | v0.1.0 |
| Workflow ref | source CI; nonpublishable rehearsal | refs/tags/v0.1.0 |
| GitHub Release | none | v0.1.0, initially a verified draft |

`scripts/release-version.py` parses normal `v<SemVer>` tags. Namespace `release/`,
branch refs, malformed versions and suffix paths are rejected. Parsing alone
never grants permission to publish. `require_production` fails before external
identity/API/registry operations while reviewed source status is `development`.
Enabling production requires a separately reviewed source change setting stable
metadata to the target and explicitly declaring `candidate`; no CLI/environment
override exists. Neither development versions nor other stable versions pass.
The future candidate still requires signed annotated GitHub-verified tag/source,
exact protected-main ancestry, ref-movement checks, full CI, fresh scans and real
native trust before publication.

Development artifacts pin the icon to the actual source commit and include the
fixture public key without inventing a public GitHub asset URL. Future stable
candidate metadata uses normal `v0.1.0` icon and delivery-key asset links.

Early development used milestone-like SemVer labels. Their five tag refs are
scheduled for deletion after this reset's protected merge and exact-main
qualification; commits, SHA identities, signatures and PR/CI history remain.
No alternate tags are created. GitHub milestones are renamed in place to
[Phases 1–10](engineering-milestone-mapping.md), preserving IDs, issue links and
states. The [reference inventory](version-reference-inventory.md) distinguishes
active metadata, old phase labels, legacy migration contracts, generic fixtures
and external dependency versions.

## Audit limits and authorization boundaries

The pre-mutation audit found zero GitHub Releases (including drafts), zero Release
workflow runs, zero forks, no open release PR or remote release branch, and no
Artifact Hub search result. GHCR package inspection returned 403 because the
available token lacks `read:packages`; anonymous image/chart pull token requests
also returned 403. These results do not prove private packages are absent.
No actual public distribution or external consumer was discovered. If one is
found before ref deletion, stop the affected deletion and record the conflict.

No tag, GitHub Release, production package, production trust secret, package ACL
change or catalog registration is authorized by this preparation. Phase progress
uses issues/RFCs, milestones, PRs, commits and CI, without SemVer/checkpoint tags.
Any future tag/trust/dispatch/publication needs separate explicit authorization
on the fully qualified ready source after all phases.

The future Sigstore identity is
`https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/v0.1.0`,
with issuer `https://token.actions.githubusercontent.com`. Nonpublishable rehearsal
uses ephemeral local key/TSA, a loopback registry and in-memory GitHub storage,
never production credentials, GHCR writes or public transparency services.

## Administrator actions for a separately authorized trust phase

### Attest signer

1. Select an existing approved Ed25519 identity or generate one through the
   organization's externally approved key procedure. Keep its unencrypted PKCS#8
   PEM private key in restricted storage outside Git and outside evidence bundles.
   Preserve the public identity approval and custody/rotation decision separately.
2. Derive the public PEM with OpenSSL 3 using the private file as input:
   `openssl pkey -in "$signer_private_path" -pubout -out "$signer_public_path"`.
   Extract exactly the raw 32-byte Ed25519 public key as 64 lowercase hex
   characters for `HANKOSHELL_ATTEST_PUBLIC_KEY`. The release preflight checks
   the full Ed25519 public DER against the private key, not just a suffix.
   This public-only extraction also rejects a different key type:

   ```sh
   openssl pkey -pubin -in "$signer_public_path" -outform DER |
     python3 -c 'import sys; d = sys.stdin.buffer.read(); assert len(d) == 44 and d[:12].hex() == "302a300506032b6570032100"; print(d[12:].hex())'
   ```
3. Install checksum-pinned Attest 0.1.0 with `scripts/install-attest.sh`. In a
   fresh restricted temporary directory, run
   `"$attest_path" keys import --name "approved release signer" "$signer_public_path"`,
   then `"$attest_path" keys list --format json`. Require one trusted entry with
   `private_key_present: false`. Record its native 32-character lowercase ID for
   `HANKOSHELL_ATTEST_KEY_ID`; never choose a label or derive a SHA-256 prefix.
   Remove that public-only temporary directory afterwards.
4. Have a separate reviewer approve the public key and native ID against the
   identity record. Provision only the existing approved private PEM as the
   environment secret `HANKOSHELL_ATTEST_SIGNING_KEY`, using a secure input
   mechanism such as `gh secret set HANKOSHELL_ATTEST_SIGNING_KEY --env release
   --repo Alien6-Studio/hankoshell-operator < "$signer_private_path"`.
   Do not print/export its value into logs, issues, PRs or command arguments.
5. In an approved isolated process, populate the required configuration and run
   `python3 scripts/attest-release.py --check-config --attest "$attest_path"`.
   A pass establishes private/public/ID and X.509 consistency only; it does not
   constitute independent administrative approval or a TSA endpoint test.

### RFC 3161 TSA

1. Select and independently approve the explicit RFC 3161 endpoint. Configure
   `HANKOSHELL_ATTEST_TSA_URL`; do not assume the native tool's default endpoint
   is approved.
2. Obtain the timestamp **issuing authority** certificate through an authenticated
   independent channel. This is not the endpoint's HTTPS server certificate.
   Inspect it and record `openssl x509 -in "$tsa_issuer_path" -noout -subject
   -issuer -dates -fingerprint -sha256`. A reviewer must approve that fingerprint.
3. Obtain an actual endpoint-issued token over a known challenge and verify the
   expected imprint, token signature, issuer and timestamping authorization.
   Also verify an isolated receipt with pinned Attest 0.1.0 and the approved
   issuer. The native verifier checks RSA/SHA-256 token and direct issuer
   signatures, critical timestamp-only EKU and responder validity at the stated
   time; it does not perform general X.509 path discovery or revocation checking.
   A successful OpenSSL certificate parse alone is insufficient.
   With the receipt's approved public key/ID and TSA issuer in its explicit
   trust store, run `"$attest_path" verify "$receipt_path" --recompute --workspace
   "$receipt_workspace" --trust-store "$receipt_workspace/.attest/trust"
   --offline --format json`. Require all five checks, no warnings and the exact
   approved public signer in the verdict. This proof uses real approved external
   trust in its separately authorized phase, never rehearsal trust.
4. Store the approved issuer PEM in `HANKOSHELL_ATTEST_TSA_CERTIFICATE`. Retain
   the endpoint/fingerprint/challenge-verification evidence without private keys
   or credentials. A foreign certificate or bad endpoint must fail qualification.

### GitHub environment and tag protection

Keep the protected `release` environment, required reviewer, no administrator
bypass and tag-only deployment policy. Review independent approval and prevention
of self-review before first publication; the audited policy allows self-review.
Production publication must remain blocked throughout development.

The current active tag ruleset **Release tags** (ID `24645043`) covers
`refs/tags/v*`, forbids deletion/non-fast-forward updates and has no bypass actors.
It protects the future normal release namespace, but currently also prevents
removal of the five erroneous prelaunch refs. Their deletion is authorized by
the product reset after protected merge and exact-main qualification. If GitHub
rejects deletion, report the exact rule and surviving refs; do not disable it,
add an undocumented bypass or recreate those tags elsewhere. This reset changes
no administrative protection.

Before a separately authorized first release, independently review the deployment
tag allowlist and admit only the exact `v0.1.0` candidate on the qualified source.
The audited policy is `v*`; current-source guards cannot alter workflows frozen in
old refs. Required review and no administrator bypass remain mandatory. The trust
secret `HANKOSHELL_ATTEST_SIGNING_KEY` and public variables
`HANKOSHELL_ATTEST_PUBLIC_KEY`, `HANKOSHELL_ATTEST_KEY_ID`,
`HANKOSHELL_ATTEST_TSA_URL`, `HANKOSHELL_ATTEST_TSA_CERTIFICATE` and
`HANKOSHELL_ARTIFACTHUB_REPOSITORY_ID` belong to that separately approved phase.

### GHCR

An authorized package administrator must inspect both
`ghcr.io/alien6-studio/hankoshell-operator` and
`ghcr.io/alien6-studio/charts/hankoshell-operator`: existence, repository linkage,
Actions access and package ACLs. Confirm the repository's `GITHUB_TOKEN` can write
the required packages through the protected publication job. The current audit
token lacks package inspection access; anonymous pull denial cannot distinguish
private packages from absent ones.

Plan public visibility explicitly: new GHCR packages default to private. Any
visibility change needs separate authorization. After authorized package creation,
verify anonymous reads of the actual image digest and Helm chart, not just a
successful authenticated push. See [GitHub Container registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

### Artifact Hub

Register the exact repository
`oci://ghcr.io/alien6-studio/charts/hankoshell-operator` through the authorized
Artifact Hub account. Obtain its genuinely assigned UUID and set
`HANKOSHELL_ARTIFACTHUB_REPOSITORY_ID`; never use the rehearsal fixture ID.
After separately authorized publication of generated `artifacthub-repo.yml`
under OCI tag `artifacthub.io`, verify that indexing matches the assigned ID,
ownership is recognized and the actual 0.1.0 package is visible.
Verified Publisher proves catalog ownership, not a Helm signature, vulnerability
absence or independent Attest approval. See [Artifact Hub repository ownership](https://artifacthub.io/docs/topics/repositories/).

## Evidence required before closing #21

Record the independent signer/TSA approvals and real consistency checks, protected
environment metadata, package access and Artifact Hub ownership/indexing evidence.
The first separately authorized delivery must also supply independently verifiable
image/checksum Sigstore certificates with the exact tag identity, native Attest
receipt/timestamp and public assets bound to its exact source and scanned digest.
Fixture trust and a green preparation PR do not close #21.
