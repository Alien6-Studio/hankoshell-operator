# Installed bounded delegation audit

Runtime and delegation harness source: `e29b3d5de672b8a2634da10bcac6633c937e74e6`.
The [OCI summary](oci-summary.json) binds the exact scanned amd64/arm64 graph,
`sha256:a9a884b0548c1f8f1fce5aa994156dd266a48d8e26650e36d5ce5af5119a76d0`.
The six local runs used a clean, pinned checkout and completed with runner exit 0
and disposable cleanup. These are development qualification results for #71.

## Installed matrix

| Keycloak / Kubernetes | Initial graph (s) | Withdrawal (s) | Checks | Native phases | Exit |
| --- | ---: | ---: | ---: | ---: | ---: |
| [26.7.5 / 1.35.0](keycloak-26.7.5-kubernetes-1.35.0.json) | 127.439 | 10.859 | 88 | 4 | 0 |
| [26.7.5 / 1.36.2](keycloak-26.7.5-kubernetes-1.36.2.json) | 120.432 | 9.791 | 88 | 4 | 0 |
| [26.7.5 / 1.37.0](keycloak-26.7.5-kubernetes-1.37.0.json) | 111.827 | 18.068 | 88 | 4 | 0 |
| [26.8.0 / 1.35.0](keycloak-26.8.0-kubernetes-1.35.0.json) | 159.354 | 17.395 | 88 | 4 | 0 |
| [26.8.0 / 1.36.2](keycloak-26.8.0-kubernetes-1.36.2.json) | 118.623 | 19.000 | 88 | 4 | 0 |
| [26.8.0 / 1.37.0](keycloak-26.8.0-kubernetes-1.37.0.json) | 85.274 | 7.680 | 88 | 4 | 0 |

Every cell passes the same **88 fixed public assertions** and four recovery
phases: **528 cell/assertion outcomes and 24 phase recoveries** in total.
Initial convergence is bounded at 600 seconds and withdrawal at 180 seconds.
These measured observations are not production latency guarantees.

The extension is pinned separately to
`Alien6-Studio/keycloak-bounded-delegation@d9423db16e2bbe31bfb1dcc83c9a9441a18a6075`.
[26.7.5](java-26.7.5.json) and [26.8.0](java-26.8.0.json) build reports retain
16 Java test names each and the JAR hashes checked by the installed fixtures.

## Behaviors demonstrated

Actual kubelet-bound workloads authenticate over HTTPS, exchange through native
Keycloak and access a separate HTTPS resource server. That server independently
checks RS256, issuer, exact audience, expiry and resource/scope permissions.
Broader ordinary grants do not broaden delegated authority. Other resources,
scopes, audiences, issuers, subjects, foreign clients and human impersonation are
refused. The second hop works; the third hop and concurrent replay are refused
by native Keycloak.

Each native phase loses an accepted-write acknowledgement and Kubernetes status,
then refuses the verified post-commit Ready patch before another restart.
Recovery preserves native identities, authority and authentication methods.
An application metadata update refreshes the sealed reference revision while
preserving its active sibling delegation journal and native grant graph.

Stale writes and provider outage cannot expand a grant. A real 8-second token
proves expiry. A separate declared 300-second token remains valid during the
180-second withdrawal window, demonstrating the offline-JWT expiry limitation.
Cleanup blocks on an incoming foreign dependency after withdrawing issuance,
recovers a lost DELETE acknowledgement and preserves foreign state and federated
authenticators. Operator RBAC cannot mint workload tokens or mutate workloads;
constrained native credentials deny impersonation and unrelated-realm authority.

Logs from current and retired operator pods, Events and inspected Kubernetes
objects pass the credential scan. Reports retain public decisions rather than
credentials or private token claims. Hub is disabled, with **zero payloads**
inspected; this does not qualify a Hub integration.

## Source and integration evidence

[Source results](source-results.json) bind the same clean runtime SHA to the CI
unit artifact: **2,691 Go race outcomes**, zero failures/skips and all coverage
floors. [Twenty fuzz targets](security-fuzz.json) pass and all
[68 security mutations](security-mutations.json) are detected. The runtime source
also passed 373 Python tests, repository hooks and the static/chart contracts.

The later endurance-fixture batch `379ea9d` passes 377 Python tests and its
[Development CI](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39158689960).
Its [amd64/arm64 Operator binary comparison](runtime-comparison.json) is identical
to this runtime; its OCI metadata and test harness retain their separate identities.

The [full runtime CI](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39154403460)
has an [incomplete 26.7.5 / 1.35.0 cell](ci-incomplete-keycloak-26.7.5-kubernetes-1.35.0.json).
It exceeds the [600-second initial read-back deadline](ci-incomplete-wait.json)
before any recovery phase. Collected status reports `OwnershipConflict`; its
capability check is supported, and the application and three federated identities
remain Ready. The cause is unresolved. The operator log was omitted because its
sanitized file exceeded the existing 64 KiB limit. No timeout is increased and
this failed cell is not qualified by the six successful local results.

The diagnostic follow-up keeps a smaller Pod-log tail and captures only fixed
ownership booleans and native/journal counts on failure, with bounded read-only
requests. It does not change provider execution or make this failure a pass.
The [final CI summary](ci/results.json) retains all six CI reports and their
separate scanned OCI identity: **five cells pass all 88 assertions and four
recoveries; the initial 26.7.5 / 1.35.0 cell remains incomplete**. Fifty jobs pass;
that cell and the required aggregate gate fail. Two unrequested optional jobs
are skipped. Issue #71 remains open.

The source follow-up `a65f157` fixes foreground scheduling
of organization ownership retries and starts a new full matrix. That new runtime
is not qualified by this older six-cell local audit.

## Limits

Single-node disposable Kubernetes, one Keycloak replica and fixed native JWKS do
not qualify provider HA, signing-key rotation, scale, human delegation or
production trust. Offline JWTs remain valid until expiry after withdrawal.
Interrupted bootstrap attempts are retained separately and excluded from this
six-cell matrix. No protected integration, feature-branch CodeQL result or
production publication is claimed.
