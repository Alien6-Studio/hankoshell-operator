# Local delegation recovery diagnostic

The ordinary fixture completed 88 checks and all four native journal recoveries
on Keycloak 26.8.0 / Kubernetes 1.35.0. It verified post-commit status failure,
withdrawal in 13.014 seconds, real expiry, foreign-dependent cleanup refusal,
interrupted deletion and the complete credential leakage scan. Disposable cleanup
completed with runner exit 0.

This reuses scanned runtime `643f607a7cd47a59a9da0003923a00837a2a3aaa`, image
`sha256:18c0340005f81e6a4d7febd87cf769281526a5597c7badcd7f144862b5832e5b`.
The current harness and its dependencies are bound in [the source manifest](source-manifest.json).
The runtime API, controller, command and chart trees are identical to the earlier
failed `dcee6b6` runtime. No recovery fix was applied for this reproduction.

The [earlier Prepared/status-fault deadline](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39256156561/job/118080653713)
remains a retained failure with an unexplained cause. This successful diagnostic
does not resolve that intermittence, qualify the latest candidate or close #71.
The [bounded report](recovery-diagnostic.json) records the actual runtime and its
single-node limitations; it is not production or connected-installation evidence.
