# Security policy

See the [deployment requirements and trust model](docs/secure-deployment.md)
for runtime boundaries, token-derived Hub HMAC authentication and response limits.

## Supported versions

Security fixes target the latest patch release in the latest published `0.x`
minor series, and its matching Helm chart. Upgrade to that patch release to
receive fixes. Older minor series, prereleases, development builds and forks
receive no separate security backports. No long-term support branch is available.

Kubernetes **1.35–1.37** is the current qualification window. Use the latest
provider security patch within it; an end-of-life or provider-extended version
does not receive additional project qualification. See the
[Kubernetes compatibility and hardening matrix](docs/secure-deployment.md#kubernetes-compatibility-and-hardening).

Version 0.1.0 is a normal SemVer release in initial development, not a beta or
prerelease. The `v1alpha1` APIs are experimental and may change between minor
versions before `1.0.0`. Reports against `main` are welcome; deploy reviewed
tagged releases when available.

## Final OCI image vulnerability gate

Source `govulncheck` remains mandatory and is supplemented by a scan of the actual
final runtime image on **both linux/amd64 and linux/arm64**. The image includes
`/hankoshell-operator` and `/usr/local/bin/cosign`; cosign has its own versioned
module, dependencies and Go runtime. Scanning the operator's go.mod alone does
not cover that second executable or the runtime OS. Trivy must identify OS
packages, both binaries, their Go runtimes and cosign's main module version;
missing inventory or mismatched architecture/configuration identity fails closed.

The reviewed scanner is **Trivy 0.75.0**, acquired from its fixed
[upstream release](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0)
with archive SHA256 values committed in [the installer](scripts/install-trivy.py)
and a runtime version check. No scanner action/image uses `latest`. Scan failures,
unavailable databases, malformed reports and missing architectures block delivery.
A fresh database is downloaded once for both scans; its hash and metadata are
recorded. Data older than 48 hours is rejected. Release evidence must be less
than 24 hours old and match the current source revision, policy and image digest.
Database updates intentionally remain current, rather than frozen with the tool.

[The versioned policy](security/oci-vulnerability-policy.json) blocks known
**HIGH and CRITICAL vulnerabilities with an available fixed version**. It reports
all severities and unfixed findings without filtering them out of the JSON.
This 0.1.0 baseline makes actionable upgrades mandatory while retaining visibility
of issues without an upstream fix. Passing does not mean there are no unfixed,
lower-severity, unknown or undiscovered vulnerabilities; maintainers must review
those findings and can defer publication independently of the automated threshold.
This inventory-based scan does not establish vulnerable-function reachability;
source govulncheck remains separate. See Trivy's [Go binary coverage and limits](https://trivy.dev/docs/latest/coverage/language/golang/).

Only HIGH findings can receive a narrowly scoped temporary exception. There
are currently **no exceptions**. Each entry must contain an exact `cve`, `package`,
`target` (binary path or `os:<distribution>`), `installed_version`, substantive
`justification` and ISO `expires` date. Wildcards, duplicate or incomplete entries
fail parsing. Expiry is the start of that UTC date, must be in the future and
within 90 days; expired entries fail the gate even if the vulnerability no longer
appears. Review and remove exceptions through a PR. CRITICAL fixes cannot be
exempted. No `.trivyignore`, VEX or implicit scanner configuration bypass is used.

The [OCI workflow](.github/workflows/oci-security.yml) exports an OCI archive once,
retains BuildKit SBOM/provenance for each platform, and scans digest-fixed views
of the original child manifests. It verifies Trivy's configuration digest for
each platform; `--platform` alone is not treated as proof of selection. This
required job is included in the existing aggregate CI gate and the release
workflow reuses its immutable artifact ID and index digest. The publisher verifies
archive/report hashes, then copies the original graph without rebuilding. A
`staging-<run>-<attempt>` reference is explicitly non-release. The SemVer OCI tag
is assigned only after scan, source/compatibility CI, signature verification,
packaging/checksum verification and strict Continuum Attest delivery verification.
Failed gates cannot publish a new release image tag or chart.

After these gates, package promotion and GitHub draft creation are separate
network operations, not an atomic transaction. A later publication failure may
leave already verified OCI packages available. Before promotion, the workflow
commits the complete verified delivery under a non-release
`delivery-candidate-0.1.0` OCI reference. A retry resolves and restores that
checkpoint by digest, rescans its exact AMD64/ARM64 archive under the current
policy, verifies the existing Sigstore signatures and recomputes Attest evidence.
The original signed scan remains historical evidence; it cannot replace the
fresh scan required on every attempt. Matching versioned packages and draft
assets are reused, while conflicts fail before publication writes. Actions
concurrency serializes release runs; registry/GitHub administrators remain trusted
writers. GitHub Release publication is a separate manual step.

Release assets include `oci-security.json`, both complete `trivy-*.json` reports
and the reviewed policy. Their hashes enter the signed checksums and Attest
receipt. The delivered chart selects the same `image@sha256` in its default
values and Artifact Hub annotation. A SBOM is an inventory; a vulnerability
report is a database-based evaluation of detected inventory; provenance records
producer build claims; a signature authenticates content under a signing identity;
Continuum Attest signs/timestamps/recomputes the delivery bindings. None of those
alone proves absence of vulnerabilities, and Attest does not supervise the build.

The required release dry run packages the scanned image's digest and exercises
local signatures and RFC 3161 timestamps with ephemeral fixture trust. It never
publishes public packages, tags or releases. It exercises native ORAS/Helm
publication in an isolated registry, including lost acknowledgements after every
publication write; GitHub release storage is a fixture. It does not qualify production GitHub OIDC,
the release signer/TSA configuration, registry access or Artifact Hub ownership.
The Attest receipt public key is not a Helm OpenPGP chart-signing key.

## Report a vulnerability

Use GitHub's [private vulnerability reporting form](https://github.com/Alien6-Studio/hankoshell-operator/security/advisories/new).
If the form is unavailable, email [contact@alien6.com](mailto:contact@alien6.com)
with the subject `hankoShell Operator security report` to request a secure
reporting channel before sharing sensitive details. Do not disclose
vulnerabilities in public issues or discussions.

Include the affected version or revision, deployment configuration, impact,
reproduction steps and a minimal proof of concept using synthetic data.
Do not include live credentials, private keys or customer data.

## Response and coordinated disclosure

We aim to acknowledge reports within **2 business days**, provide an initial
assessment within **7 business days**, and update accepted reports at least
every **7 calendar days** until resolution. These are maintenance targets,
not a contractual response SLA.

Confirmed reports are prioritized by severity and exposure. We agree a fix,
mitigation and disclosure schedule with the reporter after triage; there is
no universal remediation deadline. We publish an advisory with affected and
fixed versions when a fix or mitigation is available, and credit reporters
with their consent. Please coordinate disclosure so users can apply it first.
