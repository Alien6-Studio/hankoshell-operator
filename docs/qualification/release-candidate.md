# 1.0.0-rc.1 qualification candidate

This candidate packages the current implementation for qualification. All APIs
remain experimental, including the three served `v1beta1` candidates; storage
stays `v1alpha1`. The stable publication gate stays closed.

Run **Release candidate** on the reviewed commit. Its downloadable artifact
contains the exact scanned AMD64/ARM64 OCI archive with embedded SBOM/provenance,
a digest-pinned Helm chart, vulnerability reports, source/image identities,
release notes and SHA-256 checksums. It creates no Git tag, registry publication,
Artifact Hub identity or GitHub Release. It does not substitute fixture signing
keys for independent publisher trust.

The same packaging can consume an existing verified OCI job artifact:

```sh
python3 -m tools.release.release_candidate --archive /path/to/image.tar \
  --evidence /path/to/evidence --digest sha256:ACTUAL_INDEX_DIGEST \
  --revision ACTUAL_FULL_SOURCE_REVISION --output /fresh/candidate --helm /path/to/helm
cd /fresh/candidate/dist
shasum -a 256 -c checksums.txt
```

Load `image.tar` into the qualification registry, preserving its index digest,
before installing the packaged chart. Its default GHCR digest is an immutable
identity, not a claim that the image has already been published there. Override
only `image.repository` when mirroring. Use the existing installation-upgrade
runbook and review ownership/credential consumer health before changing Manage.

The [Scaleway upgrade report](compatibility/2026-10-20/installation-upgrade/README.md)
records the deployed development image and actual native preservation checks.
That earlier image is not this candidate. Existing results identify their own
source revisions; a new version label does not retest them.

Stable acceptance is tracked in #21, #95, #96, #106, #107 and #110. Closing the
compatibility implementation tickets for RC1 does not ratify stable APIs or
establish historical public upgrade paths. In particular, the 24-hour continuous endurance
campaign, complete capacity/HA results, public predecessor upgrade corpus and
independent release approval are not established by candidate packaging.
The historical 0.1.0 contract selection is an unratified proposal, not a public
release or evidence of production compatibility.
