# Compatibility/support development evidence, 2026-10-16

Runtime source: Verified/GPG/DCO commit `2943933b3f6f14a3fa9bcf0487f549c1b014edf2`.
Scanned OCI index: `sha256:38285972ef6624963ac9146b5d886736892051fc56a22d1eb0ed3ca9758c286b`.
Both amd64/arm64 passed Trivy 0.75.0; installed local tests executed arm64.
No image, tag or release was published.

The complete native `protocols` shard passed against both real HTTPS Keycloak
versions: 47 passing cases and one explicit unsupported-preview skip on 26.7.5;
62 passing cases on 26.8.0. This includes `TestRealKeycloakCompatibility`, whose
hostname-mismatch assertion had failed in the preceding CI after transport error
redaction. The production gateway now preserves a typed, fixed TLS verification
category while discarding native details; the strong refusal assertion remains.
Clean-runtime Go race tests: 2,262 passing. Real Kubernetes 1.37.0 API tests:
260 passing. Existing coverage floors and 49 security mutations pass.

The adjacent two installed snapshot reports each record **19 passing checks** on
Kubernetes 1.37.0, using the same scanned runtime with real Keycloak 26.7.5/26.8.0:
explicit lifecycle opt-in, independent approval (including author/operator denial),
unlabelled/empty/tenant-a/tenant-b isolation, lost ConfigMap-create acknowledgement,
restart without recreation, and refusal/preservation of a historical cross-tenant
capture without a backup Job. Logs/Events/ConfigMaps/CRDs and credential/JWT
sentinels were checked. Uniquely named fixture clusters/registries were removed.

The frozen [focused executor](snapshot-focused.py) calls the actual installed
fixture methods and records its own and their SHA-256 identities. With the stated
archive, `build.json` and scan evidence under `.tools/compatibility-batch/oci/`,
run from the repository root with the pinned tools:

```sh
python3 docs/qualification/compatibility/2026-10-16/snapshot-focused.py 26.7.5
python3 docs/qualification/compatibility/2026-10-16/snapshot-focused.py 26.8.0
```

This is **snapshot/recovery scope only**, not the complete workload matrix. The
full installed workload job still executes every existing scenario in all six
Kubernetes/Keycloak cells. No retry, quarantine, gate removal or weaker approval
is used. The [operational follow-up](../../operations/2026-10-16/observability-runtime-2943933.json)
separately records nine passing mTLS/leader/configuration rollback checks with
the updated shared harness.

The retained [upstream review packet](upstream-review-packet.json) came from
read-only official GitHub release discovery. It suggests four newer patches,
changes no fixture pins and grants no support/compatibility or production
eligibility. The manual draft-PR path is source/unit-qualified and its GraphQL
input schema was read from GitHub; no live PR creation was authorized or run.

Schema-diff/deprecation tests use synthetic stable schemas. There is no public
predecessor, active stable comparison, conversion/Go API surface proof, completed
community review or public upgrade/rollback claim. #87 and #94 remain open for
those remaining requirements. Final-head full CI remains required before fusion.
