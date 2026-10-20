# Initial public-contract candidate qualification

Issue #86 completed on protected, GitHub-Verified main commit
[`5e66926`](https://github.com/Alien6-Studio/hankoshell-operator/commit/5e6692686d92b50f7ad5e0bb140403467e712b01),
from [PR #134](https://github.com/Alien6-Studio/hankoshell-operator/pull/134).
[CI 39403930093](https://github.com/Alien6-Studio/hankoshell-operator/actions/runs/39403930093)
passed all 61 mandatory jobs; all three CodeQL analyses passed.
The [Resolution](https://github.com/Alien6-Studio/hankoshell-operator/issues/86#issuecomment-6289591908)
records the exact scope and remaining publication boundaries.

The qualified test-merge revision is
`61276333ebfd5f4c655fe95093f3dc718d7f6a6a`; its source tree and the Verified squash
are both `70ed7584397a7c8a60401beb67b03513675b532a`.
The scanned installed OCI digest is
`sha256:b4b1e61b03ebacfb4c13299d321cd45cd1a909df4d6e0747e23a7a09cabfb421`.
[validation.json](validation.json) binds these identities and the unmodified reports.

| Retained installed evidence | Result |
| --- | --- |
| [System report](system-test.json) | 20 scenario records; six frozen public-contract fixtures; nine operational checks; 24 real-token authority checks |
| Six Fleet reports, Kubernetes 1.35.0/1.36.2/1.37.0 × Keycloak 26.7.5/26.8.0 | 93 passing assertions per cell, 558 total; two independently scoped tenants converge on real Keycloak |
| Required complete CI | Source/race/coverage, schema/conversion/storage, native providers, workloads, delegation/HA, portability, Fleet, OCI and nonpublishing rehearsal pass |

Connected lab coverage uses a private-CA Hub protocol fixture. Production
Hub/Continuum installation and independent publication trust remain separate.
The public corpus reports `NoPublishedPredecessor`; no historical upgrade is
claimed. Metadata is `0.1.0-dev.0`; all 17 resources and the three additional
beta versions remain experimental. This packet qualifies the initial development
candidate, without publishing a version or ratifying the future 1.0 contract.
