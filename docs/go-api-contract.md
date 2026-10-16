# Executable Go and conversion development contracts

`docs/go-api-contract.json` selects seven exact local packages used by the public
contract fixtures. `scripts/api-surface` reads compiler export data using the pinned
Go toolchain. It does not run package initializers. The reviewed development
snapshot in `docs/contracts/go-api-development.json` contains 1,571 exports,
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
envelope: one currently served/stored v1alpha1, conversion None, and no unannounced
deprecation warning. A new served/storage version or webhook is refused until
#91/#92 supply reviewed conversion, migration and rollback qualification. Deprecation
must name a real notice/release and appear in both warning and CHANGELOG. A future
published snapshot retains this version envelope beside the schemas and Go API.

`checkConversionContract` in
`api/v1alpha1/conversion_contract_integration_test.go` runs in every existing real
Kubernetes API cell. For all 17 CRDs it stores a declaration and public status,
reads the defaulted object, passes it through the registered typed reader and
DeepCopy, and checks spec/status and UID/generation/approval-checkpoint annotations/
finalizers. An unknown field is rejected under Strict validation rather than
silently pruned. These are same-version reader fixtures; they do not qualify
alpha-to-v1 conversion, stored-byte migration, old managedFields transfer or a
public release upgrade/rollback. The existing public plan/defaulting goldens and
all other admission/SSA/installed/security gates remain mandatory.

Run `make preflight`, `make test` and the full `make integration-test` support
matrix. Adversarial Go tests mutate signatures, tags, constants, interface methods,
pointer/promoted methods, generic constraints and alias identity. Python tests
exercise removed/changed exports, package expansion, baseline tampering, missing
public API evidence, storage flips, unreviewed webhooks and missing deprecations.
No stable maturity, public history or community acceptance is created by these tools.
