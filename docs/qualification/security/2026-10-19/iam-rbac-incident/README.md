# IAM admission, CR authority and incident collection

Local component qualification on `b9b31e58dce4e01d19b4a56d766e961caa5ce4a7`
passed 771 race-enabled API cases on each Kubernetes version (1.35.0, 1.36.2,
1.37.0), 427 Python tests through the shared preflight/hooks,
tagged integration lint (zero issues), and the beta/conformance Go race tests.
The final full chart suite also passed after its old broad-writer assertion
was updated; the corrected test and migration clarification are hash-bound
separately from that product source.
[The report](validation.json) binds exact source files and the three clean API
reports/JUnit hashes. The first incomplete local iteration is retained as such.

The live authorizer fixture checks 17 resource kinds with eight verbs, lifecycle
off/on, plus actual denied Issuer/MeshService create/update/patch/delete calls
and allowed status patches. Admission tests cover maxima, over-budget values,
empty/control-character identifiers and both alpha/beta wire versions.
The inventory reduces missing explicit field/collection bounds from 440 to 397
across 20 served schemas. Five rendered RBAC profiles are retained.

The offline incident CLI is exercised as a real process: private exclusive file
creation, symlink/overwrite refusal, duplicate/deep/oversized JSON, credential
sentinels, stale conditions and unknown decisions. Only fixed decisions and
generation/count evidence reach output; no identities, spec, journals or
arbitrary messages are retained. It has no cluster or provider client.

This is development qualification. It does not qualify public predecessor
upgrades, production behavior, all stable fields, Secret/Deployment admission
isolation or an independent audit. The audited finalizer-release workflow is
still missing. #99 and #103 remain open; full CI on the integration head remains
required. No provider, release or registry publication was performed.
