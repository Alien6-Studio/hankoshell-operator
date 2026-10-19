# Transaction HA: complete CI matrix and two local cells

Runtime: `dcee6b6e263597de3b7241a23b78e60583b3c80f`, clean isolated checkout.
Scanned OCI index:
`sha256:8ee4e7814636005322a08a18fe93739890b2066ea16b9fff2bf2c0dd7c13e9ad`.
These reports qualify selected transaction recovery and a bounded live leader
API partition. They do not qualify every journal or production HA.

## Complete six-cell CI matrix

All six HA jobs passed in
[CI 39256156561](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39256156561),
with the same exact source and scanned CI OCI
`sha256:a9b0c061e051bf18a37fd7636650d4669b8cc1d53f960e8a60176dc44813519b`.
The local OCI below is separate; neither digest is substituted for the other.
Each unmodified CI report contains 16 successful assertions, six complete
transaction checkpoints, a complete live partition and complete cleanup.

| Keycloak / Kubernetes | Natural partition handoff (s) | Isolated-holder write attempts | New-holder attempted/accepted writes |
| --- | ---: | ---: | --- |
| [26.7.5 / 1.35.0](ci/26.7.5-1.35.0.json) | 44.422 | 0 | 1 / 1 |
| [26.7.5 / 1.36.2](ci/26.7.5-1.36.2.json) | 31.294 | 0 | 1 / 1 |
| [26.7.5 / 1.37.0](ci/26.7.5-1.37.0.json) | 41.887 | 0 | 1 / 1 |
| [26.8.0 / 1.35.0](ci/26.8.0-1.35.0.json) | 32.001 | 0 | 1 / 1 |
| [26.8.0 / 1.36.2](ci/26.8.0-1.36.2.json) | 41.112 | 0 | 1 / 1 |
| [26.8.0 / 1.37.0](ci/26.8.0-1.37.0.json) | 42.994 | 0 | 1 / 1 |

## Complete local cells

| Keycloak / Kubernetes | Transaction boundaries | Live partition | Result |
| --- | ---: | --- | --- |
| [26.8.0 / 1.37.0](26.8.0-1.37.0.json) | 6 | 31.304 s, 12 samples, 34 refused API requests | Pass; 16 assertions; cleanup complete |
| [26.7.5 / 1.35.0](26.7.5-1.35.0.json) | 6 | 33.674 s, 16 samples, 40 refused API requests | Pass; 16 assertions; cleanup complete |

Both partitions observed the original process alive and natural lease expiry,
without administrator Pod deletion. Each recorded zero configuration-write
attempts from the isolated caller and one attempted/accepted write by the new
holder. Sampling gaps stayed below the existing 45-second bound. The other six
transaction checkpoints separately deleted the exact holder at accepted-write
boundaries. See the [scenario contract](../../../../transaction-failover.md).

The first 26.8.0 invocation refused setup because its tools directory was a
symlink instead of an ignored directory. It created no cluster or scenario; the
fresh complete report follows correction of that checkout layout. No failed
transaction result was replaced. Both completed runners exited zero.

The full CI aggregate is separate from these six successful HA jobs. Its current
outcome must be checked in the linked run; this packet makes no claim that the
aggregate passed. Delegation HA, clock skew, broader
partitions and endurance are not qualified by these reports. The older B1
candidate's failed delegation cell remains a failure and is not overridden.

[SHA256SUMS.json](SHA256SUMS.json) binds all eight unmodified public reports.
