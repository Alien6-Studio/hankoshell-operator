# Transaction HA: two completed installed cells

Runtime: `dcee6b6e263597de3b7241a23b78e60583b3c80f`, clean isolated checkout.
Scanned OCI index:
`sha256:8ee4e7814636005322a08a18fe93739890b2066ea16b9fff2bf2c0dd7c13e9ad`.
These local reports qualify selected transaction recovery and a bounded live
leader API partition. They are not the full six-cell or production HA verdict.

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

The [full CI run](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39256156561)
is separate from these local results. Its current outcome must be checked there;
this packet makes no claim that it passed. Delegation HA, clock skew, broader
partitions and endurance are not qualified by these reports. The older B1
candidate's failed delegation cell remains a failure and is not overridden.

[SHA256SUMS.json](SHA256SUMS.json) binds the two unmodified public reports.
