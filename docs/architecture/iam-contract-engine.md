# IAM contract engine: 0.2 foundation

This decision resolves [RFC #22](https://github.com/Alien6-Studio/hankoshell-operator/issues/22)
and the execution boundary of [RFC #23](https://github.com/Alien6-Studio/hankoshell-operator/issues/23).
It is implemented for `HankoResourceServer` and `HankoRole`. Keycloak remains the
only backend. Other controllers retain their current implementation.

## Vocabulary and lifecycle

| State | Responsibility | Representation |
| --- | --- | --- |
| Normalized portable intent | Domain compiler defines explicit semantics and defaults, with logical resource relationships. | `authorization.Intent`, `roles.Intent` |
| Resolved references | Operator resolves namespace-local Hanko relationships, validates scope and local authority; adapters receive realm/role names and client identifiers. | Domain `ResolvedReferences` |
| Capability evidence | Adapter declares domain semantics and the qualification source/window. Runtime discovery cannot demand additional privileges. | Domain `CapabilityEvidence` |
| Executable provider plan | Local compiler binds intent, resolved semantics and required capabilities; execution checks freshness. | Domain `Plan` |
| Observed provider state | Adapter reads bounded responses, preserves owned IDs and reports domain observations. | Domain `State` |

```text
normalize → resolve references → evaluate capabilities → compile locally
         → validate execution preconditions → adapter → Keycloak → observe
```

`internal/iamcontract` contains only versioned digests, backend identity,
classifications/findings, plan identity, local preconditions and safe errors.
Business operations remain in domain-specific drivers. There is no universal
provider interface and no second production adapter.

Plans are sealed in-process snapshots, not public Kubernetes objects. **No
`HankoPlan` CRD is introduced.** JSON serialization emits identity only; decoding
that identity cannot reconstruct an executable plan. A zero-value/uncompiled plan
is refused. This decision can be revisited when API stability or fleet transport
requires storage; it does not preselect a future Hub trust protocol.

## Canonicalization and identity

The internal version is `hanko.sh/iam-contract/v1alpha1`. It versions normalization
and execution semantics, independently of `hanko.sh/v1alpha1` Kubernetes APIs.
Every digest is `sha256:<hex>`, with length-prefixed version/domain/purpose
separation. Domains marshal explicit semantic structs, never entire CRs, reflection
dumps, status or provider responses.

**Intent identity differs from execution-plan identity.**

| Domain | Intent identity | Plan identity |
| --- | --- | --- |
| Authorization | Name, logical realm/application relationships, audience, display name, scopes, resources and allow-only permissions/principals. | Intent hash, Keycloak backend, version, required capabilities and resolved provider-facing semantics. |
| Roles | Logical realm relationship, name, description, composite meaning and additive child-role set. | Intent hash, Keycloak backend, version, required capabilities, resolved realm, resource owner UID and native attribute metadata. |

Scopes/resources/permissions are name-keyed sets. Resource URIs, scope/resource
bindings and principals are sorted; duplicate entries in semantic sets normalize
consistently. Kubernetes admission/controller validation continues to reject
invalid duplicate object names/references. Composite role membership is an
additive set: existing extra composites remain, as in 0.1. The composite flag
normalizes to true when children are declared, matching that existing behavior.
Nil and empty collections normalize identically. Native role attribute map keys
use canonical JSON ordering; values retain their list order. Meaningful semantic
changes, resolved targets, native metadata and contract-version changes change the
appropriate identity. Metadata resourceVersion, timestamps, status, managed fields
and provider-generated IDs are excluded from both semantic hashes.

The owner UID in a role plan is deliberate execution authority, not a volatile
provider observation. Authorization owned IDs remain separate apply-time
preconditions; they do not redefine portable intent. No plan hash is a signature,
authorization credential or evidence of an atomic transaction.

## Capabilities and findings

Capabilities stay domain-specific. Authorization extends its existing
`Capabilities`; roles declare realm-role, composite and native-metadata support.
Evidence names static adapter knowledge and the real qualification window
**26.7.5 / 26.8.0**. This means the mapping is qualified in that window, not that
the current installation/version was discovered or proved identical. No discovery
request, `realm-admin`, global administrator or extra master role is introduced.
Outside that window behavior is unqualified; see the existing
[compatibility limits](../secure-deployment.md#keycloak-compatibility).

`lossless`, `lossy` and `unsupported` are typed classifications. Anything other
than lossless in desired capability evidence fails before mutation. There is no
generic loss-acceptance policy in this foundation. Unsupported capability checks
return domain errors and existing bounded status findings. Observe may report
unsupported native objects as **read-only observations**; those findings do not
authorize managing them. Messages are locally authored; individual fields and the
native-observation finding count (256) are bounded. Native response payloads and
remote object names are not copied into those findings.

## Local authority, freshness and ownership

The operator owns reference resolution, reserved-authority checks, mode/import
policy and ownership. A compiler cannot change non-reference semantics during
resolution. Plans deep-copy collection inputs. Before mutation the controller
re-fetches the source and re-resolves dependencies, recompiles, and compares
identity and preconditions: source UID/generation, referenced UID/generation,
authority mode/provider-selection labels, and authorization ownership snapshot.
Changed inputs/capabilities are rejected. Adversarial unit fixtures exercise this
boundary, including semantically changed references and ownership.

These are local freshness checks, **not a distributed transaction**. Kubernetes
cache lag and a change after the final check or between multiple provider calls
remain possible. Keycloak has no qualified compare-and-swap transaction for this
graph. Reconciliation retries converge; they do not roll back earlier writes.
Issue [#27](https://github.com/Alien6-Studio/hankoshell-operator/issues/27) completes
externally observable applied/evaluated generations, observation evidence and
stale-plan status. This PR does not add those CRD fields.

Authorization retains its owned scope/resource/policy/permission IDs, no implicit
adoption, Observe/Manage and owned cleanup. The legacy
`hanko.sh/authorization-plan-hash` annotation is ignored as execution evidence.
The existing `appliedPlanHash` is set from local successful Manage compilation;
Observe clears it. Scope/resource drift is observed, while complete
policy/principal drift evidence belongs to #27. Observe does not assert a fully
drift-free graph. The resource server owns the backing client's authorization
mode; cleanup deletes only stored owned objects. Keycloak's disabling toggle removes
the entire graph, so the adapter keeps that mode enabled if unowned objects remain.
An empty graph can be disabled; retries skip absent IDs and already-disabled graphs.

`HankoRole` has only realm roles; application client roles remain in
`HankoApplication`. HankoRole has no public mode field. Its existing import label
is treated as read-only: no provider writes or cleanup. Manage records the resource
UID in Keycloak's `hanko.sh/role-owner` attribute. Same-named unmarked/foreign roles
are refused; deletion rechecks the marker and never deletes a foreign role.
Descriptions, attributes, composite additions and reserved-authority safeguards
remain supported. Renaming a role does not clean up its previous provider name;
use deletion/recreation for changes to realm/name and inspect residual objects.

**Migration from an early 0.1 source installation:** existing HankoRole-created
roles have no ownership marker. They are now refused rather than silently adopted.
An administrator must review the role, its composites and the owning CR UID, then
explicitly assign `hanko.sh/role-owner` to that UID through Keycloak administration,
or remove/recreate the intended managed role. A finalizer or prior Ready condition
alone does not authorize adoption/deletion. Never assign this marker to a foreign
role merely to make reconciliation succeed. Direct CR attributes cannot override
the ownership marker. This marker is not cryptographic proof against a Keycloak
administrator; the trust boundary still includes the administrator and Kubernetes
writers authorized to manage IAM CRs.

## Secrets and observations

Neither migrated domain has a Secret dependency. Realm/role/application/account
resolution reads declared identity semantics and safe object metadata, not Secret
objects or client status credentials. Connection credentials stay inside the
existing Keycloak client. Plans serialize only identities; no native attributes,
provider representations, bearer tokens, passwords or private keys enter public
evidence, Kubernetes status, Events or Hub. Declared role attributes are public
metadata, never a credential store; explicit credential-shaped keys are refused.
Metadata values must not contain secrets. The adapter preserves this native
metadata privately for reconciliation and binds its declared semantics in the
plan hash, rather than exporting it.

Provider responses keep existing HTTP byte budgets. Domain errors render only a
fixed local message while preserving internal error identity; remote response
bodies cannot be echoed to conditions/logs. Credential-sentinel tests cover plan
JSON, findings, errors and controller status/Events/logs. No connected-mode payload
or Continuum implementation changes. Bundles retain their current token-derived
HMAC contract; plans are neither distributed nor independently signed here.

## Qualification and next decisions

`internal/iamconformance` is a test-only behavior helper, not a production adapter.
Both real Keycloak domains use it for deterministic compile, refusal before writes,
Observe, idempotence, drift repair, foreign-object rejection and owned deletion.
Admin events count actual writes; bootstrap only provisions identities and injects
drift/foreign objects. The normal account uses target-scoped `manage-realm`,
`manage-clients`, `manage-events`; observers use only read roles. Existing denied
operations remain required. The reviewed inventory adds only the bounded
associated-policy GET needed for permission idempotence, tested under the same
write/read roles and denied to an unprivileged service account. No role grant expands.

The exact-image installed-system suite also reconciles a HankoRole through the
running manager and checks the ownership marker, description and finalizer cleanup.
All existing Kubernetes, provider, OCI, supply-chain and release rehearsal gates
remain mandatory. Chart/app release metadata stays **0.1.0**: introducing a new
development version convention is separate work; the immutable v0.1.0 tag keeps
its original source/workflow. Development changes are recorded under 0.2 Unreleased.

Next: #27 for public evidence/status; #28 for standalone organization readiness
versus configured optional projection. Provider parity is not assumed. Realm and
application migration is staged according to the
[field boundaries](provider-boundaries.md), without flattening native Keycloak
features or introducing new public APIs in this foundation.
