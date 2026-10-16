# Credential concurrency and sustained native qualification

Runtime `30308d42a8dbe4fb05ec1ac3448a44cf606b737d`, scanned multi-architecture index `sha256:6c6fcf24f070e6c46a56a947043a8252837814ea9a91bbe541aba4f4628bf7fb`.
Both runtime architectures passed Trivy 0.75.0 with SBOM/provenance; the installed
local fixtures execute arm64. No image, tag, release or merge was published.

The [source summary](source-results.json) records 2,300 Go race tests, 310 Python
tests, both complete native Keycloak suites and coverage/lint/architecture/vuln
checks. Each native suite includes every ordinary tagged-package test and the
reviewed real-provider inventory. Expected preview skips are listed explicitly.
The real HTTPS concurrency fixture validates 256 successful reads, a 128-caller
429 wave/recovery, one token request across three guarded views and at most eight
HTTP requests in flight, plus two waves of 32 application reconciliations with
unchanged native UUIDs and converged status. Kubernetes is fake in that fixture;
this is not an installed production scale bound.

Both historically failing tests passed **20 consecutive independent attempts**
on clean runtime 30308d4 and Keycloak 26.7.5. The [adoption](adoption/stability.json)
and [protocol](protocols/stability.json) aggregates retain all forty bounded
per-attempt outcome reports beside them. JUnit references identify files in the
local/workflow artifact bundle; JUnit payloads and private logs are not committed.
No failed attempt was retried or quarantined. Earlier source 42d058f exposed a
rotation regression; [its qualification is explicitly excluded](initial-run-unqualified.json).
After the code fix, both series restarted from attempt one on 30308d4.

The [49 security mutations](security-mutations.json) passed on this same clean
source. The [OCI scan binding](oci-security.json), [69 installed Fleet checks](fleet-kubernetes-1.37.0-keycloak-26.8.0.json)
and [nine operational checks](../../../operations/2026-10-16/observability-runtime-30308d4.json)
bind this exact source and digest. The local installed cell is Kubernetes 1.37.0 /
Keycloak 26.8.0; full CI still supplies all supported cells. Fixtures remove only
their own disposable clusters/containers and retain no credentials in reports.

The [twenty-main-run read](main-history-gaps.json) found zero usable reports and
220 missing suite reports. Missing history cannot establish stability. #110 still
requires its main history window and measured GitHub whole-shard timing below
ten minutes. #95 still requires real API-server scale/concurrency, hundreds and
thousands of objects, observed resource bounds and a soak of at least 24 hours.

Reproduce with [the documented commands](../../../../keycloak-concurrency.md),
`make coverage`, the complete native suites for both versions, security mutations,
and the installed fixtures using the exact scanned archive and reviewed tools.
The eventual evidence commit changes documentation and its integrity test only;
runtime files remain identical. Complete CI on the final pushed head remains
required before fusion; this evidence does not grant production eligibility.
