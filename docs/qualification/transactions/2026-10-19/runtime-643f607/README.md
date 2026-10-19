# Delegation HA: four completed native journal handoffs

Runtime: `643f607a7cd47a59a9da0003923a00837a2a3aaa`, clean isolated checkout.
Scanned local AMD64/ARM64 OCI:
`sha256:18c0340005f81e6a4d7febd87cf769281526a5597c7badcd7f144862b5832e5b`.
Keycloak **26.7.5**, Kubernetes **1.35.0**, two operator replicas and four IAM
workers. Extension pin remains `d9423db16e2bbe31bfb1dcc83c9a9441a18a6075`.

The [unmodified installed report](delegation-26.7.5-1.35.0.json) passed all
**40 assertions and four handoffs**, with runner exit zero. At each accepted
`Prepared`, `Applied`, `Verified` and `Committed` write, its acknowledgement was
lost and only the actual holder Pod was deleted. A different lease-matched
metrics leader and two serving replicas returned. No status, journal, approval
or replica-count rewrite completed recovery.

Each handoff retained exactly four ordered journal document changes from the
appropriate holders, no native object creation/deletion attempts, the original
physical identities/inventory, grant authority, actor-owner attributes and
federated authentication. Real exchange and the independent HTTPS resource
verifier checked allowed access and denied resources/scopes after each handoff.
Credential-leakage assertions passed. Initial graph convergence took 127.236
seconds, within the unchanged 600-second budget.

[cleanup.json](cleanup.json) records the independently confirmed disappearance
of this disposable cluster and registry after successful runner completion.
No fixture names or credentials are retained. [SHA256SUMS.json](SHA256SUMS.json)
binds both records.

This is one local delegation HA cell. The 26.8.0 / 1.37.0 local fixture was
started separately; it is not a completed result here. The required
[six-cell CI on this source](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39259353855)
is separate. Ordinary installed adversarial/revocation/status-loss qualification
(#71), clock skew, broader partitions and endurance are not replaced. See the
[scenario contract](../../../../transaction-failover.md) and the preceding
[complete transaction/partition CI matrix](../runtime-dcee6b6/README.md).

The follow-up evidence commit changes documentation/reports only. Runtime code,
chart, APIs, workflows, dependencies and qualification scripts remain those of
the immutable runtime named above; its scanned OCI and report are not relabelled
as another revision.
