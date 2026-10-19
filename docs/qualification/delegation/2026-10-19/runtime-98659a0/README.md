# Installed delegation: complete CI qualification

This packet retains the twelve original public JSON reports from
[CI run 39309747558](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39309747558),
attempt 1. All 61 required jobs passed. PR #133 merged through the protected
squash `7ff8086bda255b2d7ccb429b7162766237f76225`, verified by GitHub.
The qualified PR merge `98659a0b0a5a23a803e1e716034ced38295ad722` and that squash
have the same source tree, `bb5a01b8f2ccc932747e9303874a65eff132ecd4`.

The [validation manifest](validation.json) binds each unmodified report, its
SHA-256, origin artifact, CI job and scanned image. The image is
`sha256:1e7aea055b6264ec8f0e5c86c663179e561119875d284b405c2b61c058136ef4`.
Reports retain the qualified revision and per-version extension JAR identities;
they are not relabelled as results for subsequent source changes.

| Matrix | Completed cells | Assertions | Native phase recoveries |
| --- | ---: | ---: | ---: |
| Installed delegation | 6 | 528 (88 per cell) | 24 |
| Two-replica delegation handoff | 6 | 240 (40 per cell) | 24 |

Both matrices cover Keycloak 26.7.5 / 26.8.0 × Kubernetes 1.35.0 / 1.36.2 / 1.37.0.
Every fixed assertion is true and every report is complete. Initial graph
convergence ranges from 65.825 to 215.000 seconds within its 600-second budget;
grant withdrawal ranges from 10.191 to 53.089 seconds within its 180-second bound.
No failed cell or retry is counted as a passing cell.

Actual kubelet-bound federated workloads exchange tokens over HTTPS and access
an independent resource verifier. Real flows enforce issuer, audience,
resource/scope intersection, depth, one-use replay, expiry and withdrawal.
The third hop is refused by the native provider. Adversarial cases cover wrong
identity/realm, human impersonation, a foreign client, disabled exchange,
stale intent, provider outage and foreign cleanup dependents.

Recovery preserves authority and authenticators after accepted writes with lost
acknowledgements at Prepared, Applied, Verified and Committed. The restart matrix
also loses Kubernetes status and refuses the actual post-commit status write;
there is no fictional intermediate status write. The HA matrix replaces the live
leader at every native phase and records unchanged inventory/authority. Final
checks inspect retired/current logs and Kubernetes objects for credential/token
leakage. Hub is disabled, with zero payloads inspected. Workload token minting and
workload mutation remain refused to the operator identity; constrained provider
credentials are checked independently.

This complete CI packet supersedes the earlier failed-cell qualification gaps
recorded for #71. Those historical failure packets remain available. The newer
sensitive-write chart and security changes must still pass their own exact-image
CI; this packet does not qualify a future compiled image. The issue Resolution
binds the final protected integration and its Verified squash.

These are disposable development fixtures: one Kubernetes node and one Keycloak
replica, with two operator replicas in the HA matrix. An already issued offline
JWT remains valid until its bounded expiry after grant withdrawal. Keycloak
cluster failover, signing-key rotation, production capacity/trust, public release
and stable graduation are outside this packet. `publishable` remains false.
