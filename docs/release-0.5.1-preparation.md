# 0.5.1 preparation and administrator checklist

0.5.1 is the first intended public-distribution candidate. It retains the complete
0.5 IAM contract, including the accepted target-realm HankoRole `manage-realm`
exception, and adds only release-trust consistency hardening plus version metadata.
The 16 v1alpha1 APIs remain experimental in initial development.

[#54](https://github.com/Alien6-Studio/hankoshell-operator/pull/54) was merged as
`7e0063704738ef9e63968b79d9e553555c2f2eb0`. Source qualification does not approve
production trust or publication. [#21](https://github.com/Alien6-Studio/hankoshell-operator/issues/21)
remains open until its real external evidence is available.

## Historical 0.5.0 and version inventory

`v0.5.0` is a historical tag — not published. Its signed annotated tag object
`671250d37407f083d8717345d03ff1d2e9867415` targets
`335b88c98ac25ce288648a3414387f25d76c04ff` and must not be changed, deleted or
recreated. It will not become a public image, chart or GitHub Release. No user
needs to migrate from a public 0.5.0 package.

The preparation inventoried `git grep -n '0\.5\.0'` and
`git grep -n 'v0\.5\.0'` before editing. Active chart/app metadata, build and scan
version arguments, rehearsal/checkpoint fixtures, release identity examples and
current compatibility documentation become 0.5.1. The following remain unchanged:

- Historical CHANGELOG text, milestone names/links and completed 0.5 adoption
  architecture describe the original functional baseline.
- API/CRD comments describing limits in 0.5.0 still apply to the unchanged patch;
  no Go/API schema change is needed.
- The chart icon references the existing immutable v0.5.0 source asset. Its bytes
  are unchanged; it is not a product version or image identity.
- Generic registry-error fixtures and the rejected historical prerelease test
  retain their original version examples.
- `github.com/jonboulle/clockwork v0.5.0` is a dependency version, not an operator
  version, and remains pinned unchanged.

Current release-contract checks reject 0.5.0, but this does **not** disable the
workflow stored in the historical tag. There is no main-workflow checkout/publish
bypass: eligibility continues to require `github.ref == refs/tags/<tag>`.

## Authorization boundaries

Complete source qualification and protected merge first. Stop before creating
`v0.5.1`. A separate authorization must identify the exact qualified, GitHub
Verified main commit for its signed annotated tag. Tag authorization is separate
from production trust provisioning, a Release workflow dispatch and publication
of the resulting GitHub draft. None of these actions is performed by preparation.

The future certificate identity is
`https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/v0.5.1`,
with issuer `https://token.actions.githubusercontent.com`. The workflow uses the
actual workflow/ref context; a main-ref run cannot satisfy tag eligibility or
produce that tag-bound identity. Rehearsal reports only the signing intention,
using ephemeral local trust and `publishable: false`.

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

### GitHub environment and historical-tag guard

Keep the `release` environment, required reviewer, no administrator bypass and
tag-only deployment policy. Review whether independent approval requires
preventing self-review; the observed policy currently permits self-review.
All trust settings should be scoped to this reviewed environment:

| Kind | Name |
| --- | --- |
| Secret | `HANKOSHELL_ATTEST_SIGNING_KEY` |
| Variable | `HANKOSHELL_ATTEST_PUBLIC_KEY` |
| Variable | `HANKOSHELL_ATTEST_KEY_ID` |
| Variable | `HANKOSHELL_ATTEST_TSA_URL` |
| Variable | `HANKOSHELL_ATTEST_TSA_CERTIFICATE` |
| Variable | `HANKOSHELL_ARTIFACTHUB_REPOSITORY_ID` |

Reject every request to approve historical v0.5.0. An optional non-destructive
administrative guard is to replace the environment's broad tag pattern `v*`
with an explicit allowlist of approved publication tags, initially `v0.5.1`.
Under Settings → Environments → release → Deployment branches and tags, select
tags only, add the approved exact tag and remove every overlapping rule that
also admits v0.5.0. Maintain that allowlist as later tags are separately approved.
This blocks the historical publication job at the environment gate; it does not
prevent its read-only eligibility/qualification jobs from starting. It preserves
the actual tag/workflow identity and does not mutate Git. Preparation makes no
administrative change. See [GitHub deployment environment policies](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

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
ownership is recognized and the actual 0.5.1 package is visible.
Verified Publisher proves catalog ownership, not a Helm signature, vulnerability
absence or independent Attest approval. See [Artifact Hub repository ownership](https://artifacthub.io/docs/topics/repositories/).

## Evidence required before closing #21

Record the independent signer/TSA approvals and real consistency checks, protected
environment metadata, package access and Artifact Hub ownership/indexing evidence.
The first separately authorized delivery must also supply independently verifiable
image/checksum Sigstore certificates with the exact tag identity, native Attest
receipt/timestamp and public assets bound to its exact source and scanned digest.
Fixture trust and a green preparation PR do not close #21.
