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
