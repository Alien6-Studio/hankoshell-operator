# Executable contracts and installed qualification, 2026-10-16

Runtime `49f2c752d52e9e6f8dc95afa93dfa2807cb33e5a`, scanned OCI index `sha256:77b6980639cb2f80516a955a334941b622e3effd7ee0cff21f6dc96111a18975`. Both amd64/arm64
passed Trivy 0.75.0, with SBOM/provenance; local installed executions used arm64.
All commits are signed/DCO. No image, tag, PR or release was published.

The [source summary](source-results.json) records 2,282 passing Go race tests,
303 Python tests and three real Kubernetes API cells with 278 passing tests each.
The new 17-kind typed-reader round-trips preserve stored/defaulted spec/status,
UID/generation, annotations and finalizers and reject unknown fields under Strict
validation. API runs use clean source 68fef24; the complete `api/`, schema/chart
templates/values and Go module files are byte-identical through runtime 49f2c75.
The seven-package, 1,571-export Go fixture snapshot is identical from Darwin/arm64
and Linux/amd64 compiler exports. None of these are stable interversion conversion
or public release upgrade/rollback proofs. #94 stays open for those requirements.

Two **complete installed Fleet fixtures** on Kubernetes 1.37.0 pass all
69 checks on Keycloak 26.7.5 and 69 on 26.8.0.
Adjacent reports retain every boolean decision: signature/target/authority refusal,
independent approval, journal/cache recovery, offline execution, rollback,
expiry, actual provider state and credential-safe Hub payload inspection.
The diagnostic regression was fixed by explicitly inventorying the Tenant/Fleet decisions and their Event
identity while discarding caller text; the custom-series ceiling is 1,114.
An earlier 80b54a8 local Kind bootstrap failed before any checks. Later diagnostic
failures drove the explicit code fixes. Both final fixtures are fresh executions
of 49f2c75; there is no automatic failed-test retry, weaker gate or quarantine.

The full [standalone installed system report](system-runtime-68fef24.json) passed
on source 68fef24 (including its public corpus, restart and nine operational checks).
Later changes to the runtime were limited to the fixed Tenant/Fleet Event vocabulary and routing;
the latest runtime separately passed both full Fleet fixtures and the [nine-check
mTLS/leader/configuration rollback smoke](../../../operations/2026-10-16/observability-runtime-49f2c75.json).
The harness now waits for the actual rollout before choosing Pods and does not
count a broken port-forward, timeout or HTTP 500 as an authentication refusal.

The retained [49-mutation report](security-mutations-f6b9e9b.json) passed on f6b9e9b;
all protected source files are unchanged through 49f2c75. Coverage floors,
integration-tag lint, vulnerability, Helm, generation, contracts and hooks pass.

Reproduce source/API with `make test` and `make integration-test` for every version
in versions.json. Installed fixtures are `scripts/fleet-installed-test.py` and
`scripts/observability-installed-test.py`, with the exact archive/scan evidence,
full revision/digest and pinned tools. The standalone report uses
`scripts/system-test.py` and its stated source/image. Fixtures clean their uniquely
named clusters/registries and keep credentials temporary; retained reports contain
no raw envelopes, credentials or tenant data.

This is development evidence: local Fleet runs cover two of six installed cells,
not the full support matrix. No real published predecessor, stable conversion,
storage migration, public support ratification, production HA/soak, live connected
installation/decommission or first delivery is established. Complete final-head CI
remains required before fusion; no production eligibility is granted.
