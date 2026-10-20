# Installed transaction recovery across leader replacement

This development fixture extends #96 with two actual operator replicas, the
scanned exact-source OCI archive, real HTTPS Keycloak and external fault proxies.
It includes six accepted-write checkpoints and one live-holder API partition.
A separate installed delegation fixture adds its four native journal phases.
It does not qualify every journal, arbitrary partitions,
replica clock skew or production HA. The current fixture extends the caller
partition to 300 measured seconds; fresh installed reports must qualify this
stronger interval. Earlier natural-handoff reports retain their actual durations.

The [current transaction packet](qualification/transactions/2026-10-19/runtime-dcee6b6/README.md)
retains the complete six-cell CI matrix and two local cells. The separate
[delegation HA packet](qualification/transactions/2026-10-19/runtime-643f607/README.md)
retains four completed handoffs in one local cell. Each names its exact runtime
and scanned image; neither is a complete production HA verdict.
The [earlier qualification packet](qualification/transactions/2026-10-17/runtime-5d5e3f7/README.md)
preserves the preceding two cells and their initial incomplete reports.

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

## Live holder loses API access

The additional scenario selects the actual lease-holder Pod and observes its
running container identity, restart count and start time. The external API proxy
refuses only that caller's socket IP, including renewal and fresh authority
reads. Caller headers cannot select or evade the partition. The other replica
keeps its API and provider access. The administrator neither deletes a Pod nor
edits a lease or a journal, and does not change any clock.

A changed role must stay unchanged while the old holder retains its lease.
The fixture waits for natural expiry and a different holder, then requires one
attempted and one accepted provider write by the new holder, the same native
role identity, and no configuration-write attempts from the isolated caller
after the in-flight drain. It requires an actual observation of the original
process alive during the fault. Missing caller attribution, continued renewal,
early native changes, duplicate writes or failed recovery fail the scenario.
The old caller is unblocked only after these checks; both serving replicas and
one lease-matched metrics leader must recover.

The current fixture holds that same caller-specific rule for at least 300
measured seconds. After handoff it continues checking the rule, lease holder,
and old caller's attempted/accepted configuration writes. The new holder must
recover the changed role within the existing 180-second budget while the fault
remains active. Monotonic and wall sampling gaps must remain within 45 seconds.
Only then can the fixture release the partition. Public evidence records the
required interval, actual isolated duration and handoff time; unit negatives
include a delayed stale write, early fault release, lease loss and wall-clock gap.
This is a five-minute caller partition, not a five-minute loss of every replica's
API access; the latter retains its separate recovery fixture.

Per-caller addresses and native routes are private proxy control data. Public
evidence contains only fixed decisions, numeric counts, sample gaps and elapsed
time. This bounded caller partition is not a general fencing guarantee or a
replica clock-skew test. Client-go leader election alone is not treated as such
a guarantee.

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
must contain all six checkpoints, a complete `lease_partition`, `complete=true` and successful disposable
cleanup. Partial reports and unit tests do not qualify an installed scenario.
Normal full CI requires its own six-cell HA matrix on the same scanned OCI,
with a 45-minute job budget and preserved incomplete diagnostics. HA no longer
waits for an opt-in 1,000-application scale run. The full scale job runs load and
five-minute recovery without repeating the HA suite. The separate scale workflow
still includes it for an explicitly requested scale profile.
Both dispatch paths install the pinned ORAS version into the exact tool directory
used by image mirroring. The first scale CI attempt failed before provider setup
because this executable was absent; that result is not a measured load failure.

## Delegation journal handoff

`tools/qualification/scenarios/delegation_installed_test.py --ha-only` installs two operator replicas
with four IAM workers, the same scanned exact-source image and the immutable
version-matched Keycloak extension used by the ordinary delegation fixture.
The existing single-replica restart/status-loss qualification remains separate.
The required six-cell HA job runs both fixtures within its existing 45-minute
budget and retains both complete and incomplete reports. The delegation step
also runs after a transaction failure, so one failure cannot hide the other
scenario's outcome; either failed step still fails the job.

For each `Prepared`, `Applied`, `Verified` and `Committed` boundary, the proxy
accepts the native write and loses its acknowledgement. The administrator deletes
only the actual lease-holder Pod, waits for that process to disappear, then
releases the provider proxy. The standby retains API/lease access throughout.
No scale-to-zero, status reset, journal edit or approval replacement completes
the scenario. Two serving replicas and one metrics leader matching a different
lease holder must return.

Private proxy observations require exactly the four ordered **document changes**,
each from the correct holder before/after the selected boundary. PUTs preserving
the identical journal bytes are not another document change. The bounded history
rejects overflow, repeated/regressed phases, wrong callers and native object
creation/deletion attempts. Final native inventories and physical client IDs,
grant authority and federated authenticators must remain identical apart from
the requested TTL/revision. An actual token exchange and independent HTTPS
resource verifier check access and denied resources/scopes after each handoff.

The public `installed-delegation-ha` report contains fixed decisions and counts,
not caller addresses, native routes, journal digests or representations. It must
contain four complete `ha_recovery` entries and `complete=true`. This mode does
not replace ordinary adversarial, withdrawal, cleanup or lost-status evidence,
and does not qualify replica clock skew or arbitrary network partitions.

Use the same arguments as the ordinary installed delegation command, adding
`--ha-only` and a fresh `--output` path. Both modes refuse an existing report.
Build the pinned extension with `KEYCLOAK_VERSION=26.8.0 make keycloak-extension-build`
from that exact clean checkout before running locally; repeat for 26.7.5.

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
