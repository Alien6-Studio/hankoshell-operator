# Qualification evidence privacy regression

The local Authentik 2026.8.4 fixture passed its fourteen corpus scenarios and
parent test under the Go race detector after moving credentials to child process
environments. The source was dirty during this development run; the retained
summary records the exact changed-source hashes and does not claim qualification
of a clean candidate commit.

The operational smoke ran on Kubernetes 1.37.0 / HTTPS Keycloak 26.8.0 with the
existing scanned runtime 643f607 and its immutable digest. All nine mTLS, leader
handoff, credential inspection and Helm rollback checks passed using the updated
system/observability harnesses and shared privacy helper. Their exact hashes are
in the [retained operational report](../../../operations/2026-10-19/observability-runtime-643f607.json).
That report replaces the active operational evidence reference; the previous
report remains historical. Both disposable environments were cleaned up.

The bounded JWT regression tests cover repeated header prefixes, missing payload
or signature components, redaction, 2,500 small generated-input comparisons with
the previous detector, and packaging the helper into the Hub ConfigMap. These
regressions fix the causes reported by CodeQL on PR #133. Remote findings remain
subject to reanalysis; none was dismissed or accepted as a risk.
