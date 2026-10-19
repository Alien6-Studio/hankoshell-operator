# Executable Go and conversion development contracts

`docs/go-api-contract.json` selects eight exact local packages used by the public
contract fixtures. `scripts/api-surface` reads compiler export data using the pinned
Go toolchain. It does not run package initializers. The reviewed development
snapshot in `docs/contracts/go-api-development.json` contains 1,787 exports,
including signatures, constant values, named types and aliases, fields/JSON tags,
interface requirements, generic constraints and value/pointer/promoted methods.
Names use full import paths so local import aliases cannot conceal a change.

`python3 scripts/go-api-contract.py check` fails with the package, object and exact
old/new hashes for removed or changed exports. New standalone exports are additive;
changing a struct or interface is deliberately conservative because fixture users
can depend on literal layouts and interface implementations. Body-only changes
are outside this surface check and remain covered by behavioral/golden tests.
The operator imports none of the inspection tool. No dependency is added.

This is a **development fixture contract**, not a public API guarantee. A reviewed
development API change requires a migration analysis and an explicit snapshot/hash
update in the same PR. Generate a candidate outside the reviewed baseline first:

```sh
python3 scripts/go-api-contract.py snapshot --output /tmp/go-api-candidate.json
diff -u docs/contracts/go-api-development.json /tmp/go-api-candidate.json
```

Never rewrite the baseline automatically in CI or to hide an unexpected failure.
After a real publication, its authentic retained compatibility baseline must also
include `go_api`. Public API changes then require the hash-bound notice, migration,
review, release-count and elapsed-time checks of the shared compatibility policy.
The development snapshot cannot replace that public baseline.

`scripts/compatibility-gate.py check` separately checks CRD schemas and the version
envelope: v1alpha1 remains default storage; exactly three reviewed experimental
resources also serve v1beta1 with structurally identical schemas and conversion
None. The [conversion decision](api-conversion.json) freezes all fields/defaults/
validation/topology. Schema drift, silent storage flips and unreviewed webhooks
are refused. Deprecation must name a real notice/release and appear in both warning
and CHANGELOG. A future public snapshot retains the version envelope beside the
schemas and Go API. Candidate beta is not stable graduation.

`checkConversionContract` in
`api/v1alpha1/conversion_contract_integration_test.go` runs in every existing real
Kubernetes API cell. For all 17 CRDs it stores a declaration and public status,
reads the defaulted object, passes it through the registered typed reader and
DeepCopy, and checks spec/status and UID/generation/approval-checkpoint annotations/
finalizers. An unknown field is rejected under Strict validation rather than
silently pruned. The three beta resources are read and written through the opposite served
version. These fixtures do not qualify a public release upgrade/rollback,
alpha-to-v1 semantic conversion or old managedFields topology transfer. The
separate [native storage fixture](storage-migration.md#local-qualification) checks
physical encoding and preserved managedFields during alpha/beta storage rewrites. The existing public plan/defaulting goldens and
all other admission/SSA/installed/security gates remain mandatory.

Run `make preflight`, `make test` and the full `make integration-test` support
matrix. Adversarial Go tests mutate signatures, tags, constants, interface methods,
pointer/promoted methods, generic constraints and alias identity. Python tests
exercise removed/changed exports, package expansion, baseline tampering, missing
public API evidence, storage flips, unreviewed webhooks and missing deprecations.
No stable maturity, public history or community acceptance is created by these tools.

## Delegation development contract change (2026-10-17)

This unpublished-alpha batch adds optional `delegation` origin/bounds and the
`delegated` relationship to HankoResourceServer explanation status. Readers that
exhaustively switch on relationship enums must handle this new value; Go callers
must use keyed literals when constructing the extended explanation/model types.
The neutral driver adds optional delegation-planning/guard interfaces and private
UID/runtime evidence fields. Existing ordinary-driver interfaces, persisted plan
intent and non-delegation hash goldens remain unchanged. The private execution
fields are omitted from portable intent but deliberately bind delegated plan
identity; recompile/reapprove a delegated plan after its runtime evidence changes.

The development Go snapshot/hash, frozen unpublished ResourceServer schema and
security-surface inventory are explicitly updated together for these reviewed
additions. Regenerate clients/CRDs before enabling the extension. Older strict
schemas cannot store the new status origin. No spec default, resource scope,
storage version, stable API or published compatibility predecessor is added.
Existing stable/conversion/public-corpus and future publication gates still apply.

## Experimental beta addition (2026-10-19)

The new api/v1beta1 package adds 201 exports. Compiler comparison verified that
all seven existing package snapshots remain byte-for-byte equivalent; the
reviewed development snapshot/hash adds only this package. Existing alpha field
schemas and controller hub types remain unchanged. The security inventory adds
three beta schemas identical to their alpha counterparts; no RBAC rule or binding
changes. Clients can opt into beta while alpha readers continue to reconcile.
