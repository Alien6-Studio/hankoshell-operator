# Second-provider review for the stable IAM contract

Decision for #100 based on #73/#75, reviewed on 2026-10-16. The
[machine-readable review](../tools/qualification/config/contracts/stable-provider-review.json) pins all fourteen shared
semantic fixtures, their outcomes and OIDC intent goldens. The current APIs and
authentik adapter remain experimental. A **candidate** classification names a
possible future guarantee; it does not graduate a resource or ratify #89/#104.

| Semantic | Keycloak 26.7.5 / 26.8.0 | authentik 2026.8.4 | Review decision |
| --- | --- | --- | --- |
| Identity domain / realm | lossless native fixture | unsupported | experimental; logical connection selection is not portable realm management |
| IAM profile | lossless local validation plus existing realm-policy gates | unsupported | experimental; no flow/policy approximation |
| OIDC SPA registration | lossless | lossless | portable candidate for exact bounded registration intent |
| OIDC web registration | lossless | lossless | portable candidate for registration; runtime credentials excluded |
| M2M application | lossless | unsupported | experimental; no implicit service-user creation |
| SAML application | lossless native fixture | unsupported | Keycloak-native extension candidate; no portability claim |
| Realm role | lossless | unsupported | experimental pending equivalent adapter semantics; groups are not roles |
| Composite role | lossless | unsupported | experimental; no flattened role graph |
| Organization | lossless native fixture | unsupported | experimental; no organization/group hierarchy downgrade |
| Resource server | lossless | unsupported | experimental; application policies are not the resource/principal graph |
| Service account | lossless native fixture | unsupported | experimental; identity and credential authority remain explicit |
| Workload federation | lossless native trust fixture and separate real assertion gates | unsupported | experimental; JWT capability alone does not qualify Kubernetes trust |
| Bounded delegation | unsupported | unsupported | experimental and unfinished (#69–#71); no unenforced depth/lifetime promise |
| Native application extension | lossless | unsupported | Keycloak-native extension candidate; retained without silent filtering |

The two portable candidates cover the shared corpus's exact OIDC protocol/client
type, `clientID`, HTTPS redirect registrations and logical connection binding.
They exclude runtime credential delivery, Secret projections/rotation, logout
destinations, claims, role mappings, inherited security policy and native fields.
The referenced connection supplies administrator-owned flows/mappings/signing
keys; these prerequisites cannot silently replace user intent. An unsupported
attribute on an otherwise portable application refuses the whole intent.

The SPA intent golden is
`sha256:e84df49eed870f2bc7dfc10cecdf75ffb16e00cb596661941bb4ee7e920fb517`;
the web golden is
`sha256:5a8d273dbd52136d9051c9c088644932f273dfe6697b9ad213e5c6be6fddc3e9`.
Only portable intent identities agree. Execution-plan identities bind provider
and local authority and must differ. No lossy result is accepted, and no semantic
with an unsupported adapter outcome is selected as a portable candidate.

The six retained [installed reports](../tools/qualification/config/evidence/) cover all
three Kubernetes versions and both Keycloak versions, with real authentik in
each cell: **168 observed outcomes and 270 assertions**. They bind revision
`d52ab2ab7aeb9a6c7c7119280456723dfc223fac`, scanned multiarchitecture digest
`sha256:3139618f528fe373f4f351d753beb265199910de67d63da6157f1c3d1693835b`,
corpus/harness hashes and provider pins. These are historical laboratory
evidence, not qualification of later modified surfaces or production reports.
Their explicit `qualificationWindow` remains frozen with the reports. Current
CI separately runs the versions in `versions.json`, including Keycloak 26.8.1;
rotating a fixture never relabels the historical observations.
Each cell has 15 lossless and 13 unsupported outcomes. The reports preserve
negative/restart/cleanup checks and explicit operational bindings; Hub is off.

authentik **2026.8.4 registration only** remains opt-in, unsupported for production
and without parity. In particular, IAM Ready with `Operational=False` is not
application availability. Keycloak-native SAML/settings remain available and
explicitly bounded by their pinned qualification window; users are not forced
into a portable-only feature set. Other portable domain implementations remain
on the roadmap. Lack of implementation on the second adapter does not prove
that the abstract semantic can never be portable.

The [graduation criteria](stable-graduation.md) still require public production,
cross-release migration/rollback and security/operations evidence. None of these
candidates currently satisfies that complete threshold. `stable-contract.py`
freezes corpus bytes/outcomes/goldens and verifies the complete retained matrix;
#94 will extend enforcement against actual public stable baselines when present.
