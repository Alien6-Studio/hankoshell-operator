# Keycloak concurrency qualification

This development work addresses #95 and #110. Production object limits, resource
sizing, the six installed scale cells, and the 24-hour soak remain unqualified.
The [installed scale and soak driver](scale-and-soak.md) measures those boundaries
with a real API server, authenticated metrics, and a scanned exact-source image.

## Credential connection bounds

Each `keycloak.Client` connection and all its `WithMutationGuard` views share:

| Boundary | Behaviour |
| --- | --- |
| Concurrent HTTP operations | At most 8, including token acquisition and complete bounded response reads |
| Request rate | Token bucket of 50 requests/second, initial burst 50; queued waits respect cancellation/deadlines |
| Expired-token cache miss | One in-flight refresh; ordinary waiters receive that result |
| Refresh failure | One-second minimum cooldown; canceled callers do not set this cooldown |
| Token invalidation | An incremented epoch prevents an in-flight refresh from repopulating the cache |
| Fleet permission decision | Newly issued token after invocation, without joining an earlier successful observation |
| Provider 429 | Shared cooldown using `Retry-After`, or one second when absent/invalid |
| Provider 503 | Shared cooldown when `Retry-After` is present; otherwise ordinary controller backoff and journal recovery |
| Retry hint | Seconds or HTTP date, clamped to 1 second–5 minutes; native text never enters the error |
| Mutation authority | Rechecked after acquiring the budget, immediately before HTTP execution |
| Ambiguous or refused mutation | Returned to the reconciler; no automatic replay |

Admin credential rotation discards an earlier negative probe only after the
native activation succeeds, then verifies through a newly constructed client.
Only an authentication refusal (401) can trigger activation of an inactive
pending credential. A 403, 429, 5xx or transport failure keeps the old working
credential and pending journal, without issuing a rotation write.

These are engineering ceilings, not measured production capacity. Separate
credential connections, tenant clients and replicas each have their own budget.
Independently constructing clients with the same secret does not share a
process-wide registry. The configuration is fixed while production bounds are
unknown. Chart CPU/memory defaults are unchanged. A queued request's overall
deadline includes the budget wait and the HTTP operation.

The chart defaults to one worker per controller. An explicit bounded setting
enables up to eight workers for Application, Role, Organization and ResourceServer
only; see the [review and limitations](scale-and-soak.md). Other controllers
remain serial. Different controller kinds share clients through `keycloak.Pool`.

## Executable evidence

`internal/keycloak/concurrency_test.go` runs under `-race` with a virtual clock:
three waves of 1,000 callers across token expiry, failed-credential storms,
waiter cancellation, refresh invalidation, twenty fresh permission observations,
shared guarded-view rate/cooldown bounds, refusal/recovery and a queued mutation
whose authority is revoked before a slot becomes available.

`TestRealKeycloakConcurrentCredentialBudget` runs in the required `core` shard on
both reviewed Keycloak versions. A route-restricted HTTPS relay counts requests
to a disposable native provider. Three guarded views perform 256 successful
realm reads, a 128-caller injected 429 wave and recovery, using one credential
request with at most eight requests in flight. A second scoped credential then
reconciles 32 SPA applications concurrently in two waves, checking Ready/status
generations, one native client per object and preserved UUIDs. It also exercises
six applications, roles, organizations and resource servers through four shared
reconcilers, then repeats the wave and checks identities and applied plans.
The Kubernetes
client is fake; no installed scale or API-server QPS claim follows from this.

Normal fixtures reuse Docker's immutable augmentation build layer and start
fresh containers with `--optimized`. Data, accounts, credentials and TLS material
remain unique per test. Preview fixtures retain explicit feature-specific startup.
No running provider is reused and no assertion is skipped. GitHub whole-job
timing must still demonstrate the #110 ten-minute shard target.

## Twenty-attempt stability qualification

Run from a clean committed checkout with Docker and the pinned tools available:

```sh
make keycloak-stability-test \
  KEYCLOAK_STABILITY_ROOT=TestRealKeycloakAdoptionCharacterization
make keycloak-stability-test \
  KEYCLOAK_STABILITY_ROOT=TestRealKeycloakApplicationProtocolsAndFlows
```

The read-only manual `Keycloak consecutive stability qualification` workflow
runs these series independently. Each runs twenty single attempts on Keycloak
26.7.5 with fresh native fixtures, `-race`, a three-minute test deadline, JUnit,
bounded outcomes and a step summary. The aggregate binds every attempt to one
clean SHA and stops at the first failure, skip, source change or dirty outcome.
The shared Go runner records the starting revision, detects a changed checkout
after execution and fails instead of labeling an old binary with the new SHA.
Existing output directories cannot be reused to hide an attempt; choose a fresh
`KEYCLOAK_STABILITY_OUTPUT` for a new deliberate series. No failing gate is retried
or quarantined.

These series are distinct from the twenty consecutive `main` CI runs required
by #110. The history reporter must still account for that window; missing
artifacts are evidence gaps, not passing runs.
