# Development backlog for the 1.0 workstream

Snapshot: 2026-10-20, after protected PR #135 and the in-place Scaleway upgrade.
**13 issues remain open.** The development branch name does not publish
a version or graduate an API. Current technical metadata is `0.1.0-dev.0`.

| Tracking category | Count | Remaining work |
| --- | ---: | --- |
| `track:qualification` | 2 | #95 capacity/endurance/sizing; #96 remaining HA faults and prerequisites |
| `track:stable-roadmap` | 9 | #87, #88, #89, #93, #101, #104, #105, #106, #107: compatibility policy, public history, API selection, upgrade paths, ratification and delivery |
| `track:external-evidence` | 2 | #21 independently verified production trust/catalog; #110 twenty-consecutive-main-run history |

Develop related issues as one batch, validate the shared final source, then push.
Close fully implemented issues at push with the commit, validation and remaining
integration evidence, as specified in CONTRIBUTING.md. Qualification issues
require their complete actual reports. Keep long runs in clean isolated worktrees.

## Completed qualification

- #71: installed delegation and two-replica recovery passed the complete matrix.
  The [retained delegation packet](qualification/delegation/2026-10-19/runtime-98659a0/README.md)
  preserves its actual runtime and the historical failures.
- #86: [initial public-contract candidate](qualification/initial/2026-10-20/runtime-6127633/README.md)
  completed on Verified main `5e66926`: 61 mandatory jobs, three CodeQL analyses,
  exact scanned image, installed system and six connected Fleet cells. This is
  initial development qualification; production Hub/Continuum and publication
  trust retain their documented boundaries.
- #99: [security audit](qualification/security/2026-10-19/bounded-contract/README.md)
  and [fixture repairs](qualification/security/2026-10-20/installed-fixtures/README.md)
  integrated through PR #134. All exact-candidate installed, fuzz, mutation,
  admission, OCI and recovery gates passed before the Resolution and closure.
- #91/#92: three experimental IAM beta candidates, lossless conversion and native
  storage rewrite/interruption/resume/rollback are implemented. Alpha remains
  default storage. #94 compatibility guards and #103 operational procedures are
  delivered; their completion does not ratify stable APIs or public upgrade paths.

## Current capacity and recovery batch

The bounded provider connection remains eight in-flight requests and 50 requests
per second, with at most seven guarded writers. The new ResourceServer settled
path uses one fresh complete native observation and its verified journal. Every
owned reference must still be represented; drift, retirement and delegation
transitions retain their full mutation/checkpoint path. No provider snapshot is
reused across attempts.

Optional per-kind IAM worker settings permit an explicit allocation under that
shared budget. Defaults stay at one worker per controller. Scale reports record
and verify each installed controller's worker count. Measurements determine any
qualified profile; a tuning example is not a capacity recommendation.

The HA fixture now retains the original caller's API partition for 300 measured
seconds after natural handoff begins, continuing stale-writer and lease checks.
This strengthened interval needs fresh exact-image results. Earlier 31–34-second
natural-handoff witnesses retain their original scope.

The old B1 capacity and endurance trials are finished failures, with cleanup
complete. The larger profile reached 408/1,000 current ResourceServers before its
3,600-second graph deadline. The soak observed 7,925.648 steady seconds before a
145.365-second wall sampling gap and process losses invalidated it. Neither is an
active or passing 24-hour campaign. Their unmodified reports remain retained.

#95 still requires completed larger capacity, uninterrupted >=24-hour endurance
and measured sizing. #96 retains arbitrary partition/clock-skew and remaining
fault coverage, plus #95 prerequisites. Existing six-cell transaction/delegation
HA success does not close these missing acceptance items.

The [existing-installation upgrade](qualification/compatibility/2026-10-20/installation-upgrade/README.md)
is deployed on Scaleway. All 109 original declaration UIDs, 16 original CRD UIDs
and the operator Deployment UID are preserved. All 57 reviewed native targets
have acquired ownership and resumed Manage, with current-generation Ready status.
Seven themes are Ready. All 30 native client configurations are preserved. Of 32
credential output targets, all UIDs and 30 data payloads are preserved; two
ServiceAccount credentials rotated early after their previous rotation timestamp
was cleared during Observe/acquisition. Both updated credentials authenticate and
have no cluster Pod/workload-template consumers. This preservation failure is
retained. The accompanying fixes cover historical rotation checkpoints, dual
legacy catalog hints, stale managed receipt output after provider outage and the
claim CLI's finalizer read-back race. Rollback, larger capacity, continuous
endurance and public release paths remain separate qualifications.

## Release prerequisites

#87/#89/#104 need actual compatibility/contract decisions and community review.
#88 needs sanitized real installation/incident/upgrade reports after publication.
#93/#101/#105 need genuine supported public predecessors and reported paths; there
is currently no published predecessor. Fixtures cannot create production history.
#110 needs twenty consecutive main-run history; development runs cannot replace it.

#106 aggregates the final ratified 1.0 candidate. #107 additionally requires the
independent verifier and second-maintainer/environment approval specified there.
#21 tracks externally provisioned signer/TSA/catalog trust. No development push
creates those independent proofs or authorizes publication.

The #104/#105/#106/#107 closure-link cycles must be resolved in final acceptance:
record contract decisions, technical qualification and delivery in that order,
without inventing earlier closures or weakening their substantive requirements.
