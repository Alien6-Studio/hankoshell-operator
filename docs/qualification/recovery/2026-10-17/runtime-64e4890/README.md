# Authoritative realm deletion and prolonged API recovery

Runtime source: `64e48902e918be843c2bed32567cc1b6898820bb`.
The [OCI summary](oci-summary.json) binds the scanned amd64/arm64 image. This
packet records development fixtures, not production HA or resource defaults.

## Changes and source checks

Managed realm cleanup now inventories all eight namespace-local realm-reference
kinds through the uncached API reader and complete pages. Unreadable or incomplete
inventory refuses deletion. After provider preflight, a final live parent read
checks UID, generation, deletion, finalizer, labels and annotations before DELETE.
Observe still preserves native state. Expected dependency waits retain the
existing `Reconciling` phase, report `Synced=False/DependenciesRemain` with bounded
kind counts, and retry at 30–35 seconds without rewriting unchanged status.

[Source results](source-results.json) record **2,426 Go race tests**, all coverage
floors, **333 Python tests**, chart, architecture, ordinary/tagged lint,
vulnerability, Actions and full repository hook checks. Real Kubernetes **1.35.0, 1.36.2 and 1.37.0**
each passed **280 tests**, including a 201-child live inventory behind a deliberately
empty cache. Real HTTPS Keycloak **26.7.5 and 26.8.0** each passed **32 core tests**.

The signed follow-up `55a74dfa15bbcf6c97c2fe095c9ab85b7a110e15` changes one Go test
and the security mutation catalog/tests. Runtime, chart, dependencies and installed
harnesses remain byte-identical. Its complete Python, architecture and lint group
passes. The new test observes actual attempted provider requests, so a removed
guard must cause a completed assertion failure rather than a nil-provider panic.

The [complete security mutation catalog](security-mutations.json) detected all
**53 mutations**. Four remove the live reader, a realm-reference kind, collection
pagination or the final authority recheck. Every unmodified baseline passes;
build errors, panics, timeouts and missing tests cannot count as detection.

## Installed evidence

The installed recovery fixture uses 400 applications, two realms and two operator
replicas. It measures five minutes of unavailable operator API transport, then
explicit cleanup of an owned realm with 222 dependents, including 200 applications.
The actual API remains independently available to the administrator. The parent
must survive while roles/organizations remain after application cleanup. An
accepted provider realm DELETE loses its acknowledgement; leader replacement
must complete the finalizer with one accepted DELETE and preserve all client
identities in the other realm. See the [executable scenario contract](../../../../recovery-and-realm-deletion.md).

Only the final complete reports with successful cleanup qualify these scenarios.
Intermediate progress and active processes do not qualify a fixture.

The [completed recovery fixture](installed-recovery.json) passed all **11 checks**
on Kubernetes 1.37.0 and Keycloak 26.8.0. It observed **300.001 seconds** of API
transport loss across 29 samples, with a maximum 10.730-second gap and 488 refused
requests. Recovery required no manual restart or status reset. The owned realm
remained while 222 declarations were explicitly cleaned up; one provider DELETE
was accepted across lost acknowledgement and leader replacement. All 200
applications in the other realm retained their physical client identities.

The [operational fixture](installed-operational.json) passed **nine checks** using
the same runtime and a corrected probe from
`f072c4893de07c7540a49d746e89e10eb4655233`. The [initial system failure](initial-system-tls-failure.json)
is retained: the server recorded certificate refusals but the client probe did
not obtain qualifying peer-alert evidence. The exact transport cause was not
established. The updated probe sends no HTTP bytes before reading the TLS
refusal, and still rejects EOF, reset, timeout and local verification failure.
The [local Go TLS regression](tls-probe-regression.json) passes 100 handshake-only
refusals and an authorized control; it did not reproduce the original failure
with the older HTTP-request mode. It is not an installed matrix result.

The [complete installed-system rerun](installed-system.json) then passed all
**20 system checks**, the **six public contract fixtures**, and the **nine
operational checks**, with successful runner exit and disposable cleanup. Its
runtime image remains bound to `64e4890`; the operational probe comes from the
explicitly recorded `f072c48` harness revision. Runtime code, chart and dependencies
are unchanged by the two test/probe follow-ups. There is no published predecessor
for cross-release qualification.

## Scope still open

The [new runtime's endurance snapshot](soak-start.json) records an incomplete
1,000-application, 10-realm run. Its active process continues in its frozen
source worktree. This snapshot is neither a final result nor 24-hour evidence.

The earlier [1,000-application result](../../../scale/2026-10-17/runtime-824c8f1/mixed-final.json)
is complete for source `824c8f1`, including all three overload recoveries and five
measured steady minutes. It does not qualify these later realm-deletion changes.

The six-cell matrix, completed 24-hour soak, larger per-kind bounds and measured
resource defaults remain required by #95. Other journal boundaries, stale-lease
split brain and replica clock skew remain required by #96. No published release,
protected merge, production HA or completed 24-hour qualification is claimed.
