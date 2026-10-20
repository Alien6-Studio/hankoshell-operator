# Frozen candidate semantics and conformance corpus

This is the #82/#84 baseline for the [selected 0.1.0 candidate](public-contract-selection.md).
It covers the selected application, role and resource-server field groups. Current
development maturity, native extensions and deferred nested authority remain as
classified there. The [machine-readable corpus](../internal/iamconformance/testdata/public-0.1.0/corpus.json)
contains synthetic declarations, stored/defaulted objects, public status and exact
compiled identities. It contains no credentials or captured production objects.

## Meaning, defaults and identity

| Surface | Frozen rule |
| --- | --- |
| Contract digest | `hanko.sh/iam-contract/v1alpha1`; SHA-256 over length-prefixed version/domain/purpose and explicit semantic JSON. Whole CRs, status and credentials are excluded. |
| Public plan JSON | Exactly `contract`, `backend`, `intent`, `plan`; serialization does not create an executable plan. |
| Application defaults | CRD `protocol=oidc`, `mode=Manage`; omitted OIDC `type` means controller-side `web` for legacy compatibility, without rewriting stored spec. SAML defaults signed assertions to true and NameID to persistent. |
| Role defaults | CRD `mode=Manage`; a declared composite child makes compiled composite meaning true even when the optional flag is omitted/false. Membership remains additive. |
| Resource-server defaults | CRD `mode=Manage`; resources, scopes and allow-only permissions retain their declared relationships. Unknown/unresolved capabilities fail before provider mutation. |
| Semantic sets | Callback/logout/ACS destinations, role membership, URI/scope/resource/principal sets normalize ordering and duplicates where the domain defines a set. API map/set topology may reject duplicate entries independently. |
| Ordered native values | Arbitrary native metadata value lists are not treated as unordered semantic sets. Native fields outside the selected boundary remain alpha. |
| Nil and empty | Equivalent for ordinary semantic collections. Omitted realm-role scopes means unmanaged; explicitly empty means managed empty, and deliberately has a different intent identity. |
| Whitespace | Identifiers and callback bytes are not globally trimmed. A whitespace change must not silently select another client or authority. Domain-specific normalization remains as frozen by its compiler. |
| Local authority | Source UID/generation, reference/authority digests and ownership are separately checked execution preconditions. Application/role resolved owner UIDs also bind their plan identity. Authorization owned provider IDs are apply-time preconditions, not portable meaning. |

The corpus exercises default omission, equivalent ordering, nil/empty distinction,
duplicate composite membership and owner replacement. Stored-spec expectations are
independent reviewed values; tests never recompute an expected default from the
current schema. A deliberately changed plan, field, default, enum, pattern or list
topology fails with the named resource/diff.

## Ownership and reader compatibility

[ownership.json](../internal/iamconformance/testdata/public-0.1.0/ownership.json)
freezes the existing UID marker names and a non-secret version-1 authorization
journal. Current readers must recover that journal unchanged, reject another UID
and reject an unknown newer format. An unmarked legacy object is not owned.
Existing provider conformance also tests foreign conflicts, Observe/no mutation,
lost acknowledgements, ownership recovery and safe deletion.

These formats must remain readable by later 0.x readers when this selected
contract is activated. A marker or semantic format change requires a migration
issue, reader/rollback analysis and explicit corpus review. A public plan hash or
historical status cannot substitute for current provider ownership or approval.
The broader [migration policy](api-migration-policy.md) governs atomic-to-map
conditions migration, CRD ordering and suspension of unreadable pending state.

## API and installed execution

The existing mandatory API matrix replays the corpus on real Kubernetes
1.35.0/1.36.2/1.37.0. It verifies exact stored/defaulted specs and public status,
idempotent SSA, preservation of foreign metadata and object UID, conflicts from a
second manager, and strict rejection of unknown stored fields. The independent
conditions fixture tests type-keyed status ownership and duplicate rejection on
all 17 CRDs. No ForceOwnership is used to conceal a conflict.

The existing exact-scanned installed-system job instantiates the same declarations
with explicit local realm/client/reference aliases. It waits for current evaluated,
applied and observed evidence, restarts the real manager and verifies native client
identity plus role/resource-server UID ownership. The generated public report binds
the corpus hash and fixture count. Private client credentials remain ephemeral
fixture inputs and join the existing log/Event/CR inspection canaries.

There is **no published predecessor**. The corpus and installed report therefore
record `NoPublishedPredecessor`; no development restart is reported as N-1 → N or
cross-release rollback. Unknown newer journals and unknown stored fields fail
closed in the present corpus. Real predecessor upgrade/rollback qualification
must be added from actual published artifacts when one exists (#93/#105); the
first-release limitation must not be silently converted into a passing path.

## Running and changing fixtures

`python3 -m tools.qualification.checks.public_contract check` checks selection coverage, frozen schemas
and corpus field coverage; release packaging invokes it. `make test` checks exact
compiler identities and old ownership readers. `make integration-test` replays the
stored corpus, and `make system-test` runs its installed behavior within the full
existing system gate. Full #86 qualification binds these gates to the final image
and source revision before publication.

After reviewing a deliberate semantic change and its migration issue, regenerate
compiler identities locally with
`UPDATE_PUBLIC_FIXTURES=1 go test -run '^TestPublicContractPlanGoldens$' ./internal/controller`.
CI refuses that rewrite flag. Review every resulting fixture diff together with
the semantic change; never regenerate away an unexpected failure. Frozen schema
snapshots and stored/defaulted objects require explicit reviewed edits as well.
Later operator releases rerun this unchanged baseline; new release fixtures add
coverage without silently replacing the initial reader contract.
