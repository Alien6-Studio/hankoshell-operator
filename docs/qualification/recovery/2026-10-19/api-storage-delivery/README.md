# API conversion and native storage delivery

The version/conversion implementation (#91) and administrator migration/rollback
implementation (#92) are delivered. [CONTRIBUTING.md](../../../../../CONTRIBUTING.md)
records implementation completion at the signed development push, independently
of final integration, public compatibility decisions and release qualification.

[CI 39296140478](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39296140478)
has completed all three API/security jobs and all three native storage jobs
successfully on integration head `3e2c55e72956b25717398e7ebba336ec94db32b7`.
The complete aggregate pipeline is still a separate gate; this packet does not
claim that every job has completed or passed.

The reviewed profile serves Application, Role and ResourceServer in alpha and
beta with structurally identical schemas, lossless typed object/list conversion
and an alpha controller hub/default storage. Real API tests cover both wire
versions, authority metadata, strict unknown-field refusal, cross-version SSA
conflicts and concurrent independent field managers. **Beta remains experimental.**
Resource graduation and the compatibility promise require #89/#104.

| Kubernetes | Native report | Fresh native migrations | Actual CLI interruptions |
| --- | --- | ---: | ---: |
| 1.35.0 | [Report](storage-1.35.0.json) | 16 | 4 |
| 1.36.2 | [Report](storage-1.36.2.json) | 16 | 4 |
| 1.37.0 | [Report](storage-1.37.0.json) | 16 | 4 |

Each native cell verifies actual etcd encoding, alpha → beta → alpha, immutable
object meaning/authority metadata, rewrite and commit process interruptions,
same approved plan resume, fresh native proof even after completed journals,
storedVersions and chart readability protection. Disposable cleanup succeeded.
Pending deletion, adoption, rotation and delegation configurations are refused
before mutation with explicit reasons when native idle state cannot be proved.

[manifest.json](manifest.json) binds the source components, API job links,
downloaded artifact digests, original report hashes and retained report hashes.
The only report normalization renames the public contract-hash key to
`contract_sha256`; no result or scope changes. This avoids a generic secret-scan
false positive without weakening the scanner. The CLI/harness/conversion/chart
components remain byte-identical to the qualified integration head.

Native storage tests use a real disposable API server and migrator with synthetic
IAM objects and a stopped operator. They do not qualify provider-state upgrades,
a previous public operator release or connected production operation. Authentic
public paths remain in #93/#101/#105 and final candidate qualification in #86/#106.
No stable graduation, tag, release, registry write or protection bypass occurred.
