# Installed operational smoke evidence, 2026-10-16

The adjacent sanitized report records nine successful checks against the scanned
OCI built from signed runtime revision `019b094df300137abf0cd729e7007f0976cd44a1`,
index digest `sha256:89c1b03e45b04612ead9a08ade3d9e6167ff48be9e48d24c1a2172b42d7dc39e`.
The chart was installed under Restricted admission on Kubernetes 1.37.0 with real
HTTPS Keycloak 26.8.0. Both runtime architectures passed the reviewed Trivy gate;
only arm64 was executed in this local kind fixture. No image was published.

The report binds the operational and shared system harnesses by SHA-256. It
contains no credentials, keys, kubeconfig, Pod names or private configuration.
The archive, full scan evidence and private logs remain local under the ignored
`.tools/operations-batch/` directory. The complete CI still needs to qualify the
final pushed candidate independently; an older green matrix is not this report.

Reproduce with the scanned archive/evidence for the stated runtime revision:

```sh
python3 scripts/observability-installed-test.py \
  --archive "$archive" --evidence "$evidence" --digest "$digest" \
  --revision 019b094df300137abf0cd729e7007f0976cd44a1 --output "$report" \
  --kind "$kind" --kubectl "$kubectl" --helm "$helm" --oras "$oras" --openssl "$openssl3"
```

The harness validates that exact archive/scan/revision/digest **before** creating
any temporary cluster/container. It verifies actual authenticated scraping,
anonymous/unapproved-URI refusal, registered controller/provider metrics, bounded
inventory, standby/leader probes, lease handoff without native identity or
credential replacement, secret sentinel absence and same-source Helm configuration
rollback. Cleanup removed only its own uniquely named cluster and registry.

This is a bounded, single-node smoke test. It does not establish production HA,
partitions, clock skew, operation-interruption coverage, cross-release rollback,
CNI enforcement, Prometheus Operator/Grafana installation or a 24-hour soak.

A follow-up runtime `2943933b3f6f14a3fa9bcf0487f549c1b014edf2` and its updated shared
harness passed the same nine installed checks. See [the new immutable report](observability-runtime-2943933.json);
the earlier report remains historical evidence. The active machine entry points
to the follow-up report and its current harness hashes.

## Follow-up: Fleet refusal identity and rollout synchronization

The immutable [f6b9e9b report](observability-runtime-f6b9e9b.json) repeats all nine
installed operational checks on the final scanned f6b9e9b runtime. The harness
waits for the actual Deployment rollout before selecting replicas and refuses
connection/timeout/server failures as evidence of authentication rejection.
Fleet/bundle refusal reasons are explicit catalog entries; text/labels remain
bounded, with a 1,045-series static custom-metric ceiling. Historical reports
remain unchanged. This smoke is not production HA/soak qualification.

## Complete Tenant decision follow-up: 49f2c75

The [49f2c75 report](observability-runtime-49f2c75.json) repeats all nine installed
operational checks on the final image after inventorying every declared Tenant
decision. The complete catalogue has 89 reasons and a reviewed 1,114 custom-series
ceiling. Both full Fleet fixtures additionally pass 69 checks each on the same
image, including offline cache, agent commands, expired decommission and recovery;
see [the retained batch](../../compatibility/2026-10-16/contracts-49f2c75/README.md).
Historical reports remain bound to their stated source and digest.
