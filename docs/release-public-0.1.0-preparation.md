# Public 0.1.0 preparation and administrator checklist

Public product 0.1.0 consolidates the complete qualified E1–E5 capabilities:
Trusted Keycloak Foundation, IAM Contract Engine, Application Identity,
Organizational Authorization and Adopt Existing Keycloak, plus #54 release-trust
hardening. The accepted target-realm HankoRole `manage-realm` exception is unchanged.
This version-model correction does not roll back to historical checkpoint v0.1.0
and makes no IAM, CRD, permission or dependency change. The earlier 0.5.1 source
preparation and tag-readiness decision were canceled before any tag/publication.
The 16 v1alpha1 APIs remain experimental in initial development.

[#54](https://github.com/Alien6-Studio/hankoshell-operator/pull/54) was merged as
`7e0063704738ef9e63968b79d9e553555c2f2eb0`. Source qualification does not approve
production trust or publication. [#21](https://github.com/Alien6-Studio/hankoshell-operator/issues/21)
remains open until its real external evidence is available.

## Public version and historical checkpoints

| Public artifact/context | Value |
| --- | --- |
| Operator / chart / appVersion / OCI image tag / Artifact Hub version | 0.1.0 |
| Git source release tag | release/v0.1.0 |
| Workflow ref | refs/tags/release/v0.1.0 |
| GitHub Release display name | v0.1.0 |

Only release/v<SemVer> is accepted by the current publication tag parser. It
rejects bare vX.Y.Z checkpoints, branch refs, other namespaces, leading zeroes,
incomplete versions, suffix paths and invalid SemVer. Syntactic acceptance of
release/v0.1.1 or release/v0.2.0 does not authorize those versions: the current
source/chart/qualification contract supports only product 0.1.0. Extraction uses
scripts/release-version.py, never ${TAG#v}. GitHub release lookup/asset and generated
icon URLs encode the slash in the tag name; namespaced Git refs never become OCI
tags or chart versions.

All five signed annotated historical engineering/source checkpoints remain
immutable and unpublished. They are not five public releases, and there is no
public-package migration from them. Their retained identities are:

| Historical tag | Signed tag object | Source commit |
| --- | --- | --- |
| v0.1.0 | 708303a0bffa1576b367e5bfdabb66866b9122b0 | f2c3d30f64db7d2bb18a621567dcc4a7f4edf07c |
| v0.2.0 | 716746207cdfb65da4c7f7a961ad32212b66b81a | bb804bec80d867c300c16595950520019723b4e9 |
| v0.3.0 | e6adf6f5ab59538d25388810ff727e061d779ec7 | d20fafd30c0e58802a672f6fc6b3c1d8b669fbce |
| v0.4.0 | 64202aff99ad2db0a53333d2ad81e5d1ca7446fa | 7c255ff6fdbf38e7a7b26777d690968b5c670a62 |
| v0.5.0 | 671250d37407f083d8717345d03ff1d2e9867415 | 335b88c98ac25ce288648a3414387f25d76c04ff |

Public release/v0.1.0 will be a distinct ref on the fully qualified current main,
not the same tag object or source as historical v0.1.0. Never move/delete/recreate
any historical tag. No v0.5.1 tag will be created. Use milestones, issues, branches,
protected commits and CI for engineering work; a separately approved source
checkpoint may use checkpoint/E6, which cannot satisfy the release parser.

Before editing, the preparation inventoried every 0.5.1 occurrence and classified
active product metadata, expected release identities, curated notes and superseded
preparation history. Current metadata, build/scan/rehearsal fixtures and compatibility
become 0.1.0. Historical CHANGELOG/API/CRD descriptions, generic registry fixtures,
third-party dependency versions and the immutable v0.5.0 icon asset stay historical.
Engineering milestones are E1–E9 in the [roadmap](../ROADMAP.md); existing GitHub
milestone IDs/titles/states and issues are preserved under the documented
[non-destructive title proposal](engineering-milestone-mapping.md).

Modern rejection does **not** alter the workflow frozen in any old tag. There is
no main-workflow checkout/publish bypass: eligibility still requires
`github.ref == refs/tags/<tag>`, with tag exclusively release/v<SemVer>.

## Authorization boundaries

Complete source qualification and protected merge first. Stop before creating
`release/v0.1.0`. A separate authorization must identify the exact qualified, GitHub
Verified main commit for its signed annotated tag. Tag authorization is separate
from production trust provisioning, a Release workflow dispatch and publication
of the resulting GitHub draft. None of these actions is performed by preparation.

The future certificate identity is
`https://github.com/Alien6-Studio/hankoshell-operator/.github/workflows/release.yml@refs/tags/release/v0.1.0`,
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

Reject every request to publish a bare historical v* checkpoint. Two existing
administrative settings currently use only the legacy namespace: environment
release has tag policy v*, and active tag ruleset "Release tags" (24645043)
protects refs/tags/v* with deletion/non-fast-forward rules and no bypass actors.
Neither setting should be assumed to protect or admit the new public namespace.
No setting is changed by this source mission.

Before separately authorized public tag creation/publication, an administrator
must review and apply these non-destructive changes under separate authorization:

1. Keep protection of historical refs/tags/v* unchanged. Extend the immutable tag
   ruleset, or add an equally enforced tag ruleset, to refs/tags/release/v* with
   no deletion, no update/force-push and no bypass. The public tag must remain
   signed, annotated and GitHub Verified on the exact qualified main commit.
2. Under Settings → Environments → release → Deployment branches and tags, use
   selected **tags** and an exact allowlist initially release/v0.1.0. Remove the
   legacy v* and any overlapping rule that admits historical checkpoints or
   branches. Add later exact public tags only when separately approved. If a
   broader reviewed future policy is chosen, its namespace must be release/v*.
3. Retain required review and no administrator bypass. Review prevent-self-review
   for independent approval; the observed policy currently allows self-review.
   Trust provisioning, dispatch and publication remain distinct approvals.

An environment allowlist gates the historical publication job without modifying
Git or changing workflow/ref identity; read-only eligibility/qualification jobs
may still start. A denylist in modern main cannot protect a frozen historical
workflow. See [GitHub deployment environment policies](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
and [tag rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets).

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
