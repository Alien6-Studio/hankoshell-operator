# Installed transaction recovery across leader replacement

This development fixture extends #96 with two actual operator replicas, the
scanned exact-source OCI archive, real HTTPS Keycloak and external fault proxies.
It does not qualify every journal, delegation apply, stale-lease split brain,
replica clock skew or production HA.

## Six deterministic checkpoints

| Transaction | Accepted write whose response is lost | Required recovery |
| --- | --- | --- |
| Secret rotation | Native `POST client-secret` | Keep the old output until read-back, then publish the new credential with one native attempt |
| Secret rotation | Canonical Secret PATCH | Resume between output persistence and status, keeping the Secret UID and one native attempt |
| Secret rotation | `Committed` journal PATCH | Recover status from the same request, without another native rotation |
| Observe client acquisition | Provider ownership/receipt PUT | Recover the exact approved receipt, preserving UUID, native fields and credential, with no Secret or finalizer acquisition |
| Observe role acquisition | Provider ownership/receipt PUT | Recover the exact approved receipt and preserved native fields, with one receipt PUT |
| Signed Fleet plan | Verified tenant checkpoint status PATCH | Create no child before durable verification; resume the same approved plan with one Kubernetes child and one native client |

The proxy forwards the original caller's authority. A rejected write does not
consume an acknowledgement-loss rule. Rotation filters select the exact journal
annotation and step; plan filters select the new verified identity, so ordinary
status updates cannot accidentally trigger the intended boundary.
Persisted Kubernetes child creation counts only non-dry-run HTTP 201 responses,
including Server-Side Apply PATCH creation. Successful dry-run POSTs and updates
cannot count as persisted creations. The first plan fixture's route-only counter
did not distinguish these operations; its incomplete result is retained.

After each accepted write, the administrator deletes the exact lease-holder pod
and waits for that process to disappear before releasing the proxies. The fixture
requires two serving replicas again, exactly one observed reconciliation leader
matching the new lease, and a holder identity different from the previous one.
It never scales the Deployment to zero, removes status or replaces approvals to
complete recovery. Metrics are sampled at the replacement boundaries; this is
not continuous proof against split brain during a network partition.

Rotation assertions compare the journal's nanosecond timestamp at the whole-second
precision of `metav1.Time` status. They also require the same request ID and current
Ready, and reject a later rotation that happens to produce another valid Secret.
Only numeric counts and fixed decisions enter the public report. Private values
are compared in memory and included in the existing credential leakage scan.

The initial fixture incorrectly expected credential-read denial on both versions.
The existing [permissions contract](keycloak-permissions.md) records that the
26.7.5 `view-clients` profile can read the native client secret, while that endpoint
is denied on 26.8.0. Reports retain
the exact version-specific HTTP outcome and refuse client writes in both cells.
This does not qualify provider-level credential-read separation on 26.7.5.
Independently, acquisition must attempt **zero** credential endpoint reads through
the operator transport, including requests refused by an active fault. No Observe
acquisition may project a Secret or rotate the native credential. The earlier
26.7.5 run that expected a 403 is retained as incomplete, not a passing HA result.

```sh
make transactions-installed-test \
  OCI_ARCHIVE="$archive" OCI_EVIDENCE="$evidence" OCI_DIGEST="$digest" \
  REVISION="$revision" TRANSACTIONS_OUTPUT="$fresh_report" \
  KEYCLOAK_VERSION=26.8.0 KUBERNETES_VERSION=1.37.0 \
  KIND="$kind" KUBECTL="$kubectl" HELM="$helm" ORAS="$oras" OPENSSL="$openssl"
```

Run from an isolated clean worktree at the supplied revision. The final report
must contain all six checkpoints, `complete=true` and successful disposable
cleanup. Partial reports and unit tests do not qualify an installed scenario.
The opt-in six-cell scale CI also executes this fixture on the same scanned OCI;
the additive scale/recovery/transaction group has a 75-minute job budget. Smoke
dispatch keeps its shorter workload. Normal CI retains its existing required gates.
Both dispatch paths install the pinned ORAS version into the exact tool directory
used by image mirroring. The first scale CI attempt failed before provider setup
because this executable was absent; that result is not a measured load failure.

## Security mutation compilation

An older CI recorded a 120-second timeout on its first mutation, without an
assertion verdict. The runner now compiles the selected race-enabled packages
first, under a separate 300-second budget and with no test execution. Cold
compilation is a possible contributor to that original failure, not a reproduced
root cause. Its completion is never a security detection or a passing baseline.
Every unmodified baseline still has to pass, and every mutation still requires
a completed failing assertion. The 120-second command, 45-second test and
900-second mutation group limits are unchanged; compilation and assertions share
the existing 20-minute CI job cap. Timeouts, malformed streams, panics and build failures
still fail the gate. Reports distinguish baseline failures from mutation failures.
