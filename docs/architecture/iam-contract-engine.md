# IAM contract engine and evidence

This implementation resolves [RFC #22](https://github.com/Alien6-Studio/hankoshell-operator/issues/22)
and the execution boundary of [RFC #23](https://github.com/Alien6-Studio/hankoshell-operator/issues/23).
It is implemented for `HankoResourceServer` and `HankoRole`. Keycloak remains the
only backend. Public evidence implements [#27](https://github.com/Alien6-Studio/hankoshell-operator/issues/27) for these two domains; other controllers retain their current implementation.

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
| Authorization | Name, logical realm/application relationships, audience, display name, scopes, resources and allow-only permissions/principals. | Intent hash, Keycloak backend, version, required capabilities, resolved provider-facing semantics and local reference/authority identities. |
| Roles | Logical realm relationship, name, description, composite meaning and additive child-role set. | Intent hash, Keycloak backend, version, required capabilities, resolved realm, resource owner UID, native attribute metadata and local reference/authority identities. |

Scopes/resources/permissions are name-keyed sets. Resource URIs, scope/resource
bindings and principals are sorted; duplicate entries in semantic sets normalize
consistently. Kubernetes admission/controller validation continues to reject
invalid duplicate object names/references. Composite role membership is an
additive set: existing extra composites remain, as in 0.1. The composite flag
normalizes to true when children are declared, matching that existing behavior.
Nil and empty collections normalize identically. Native role attribute map keys
use canonical JSON ordering; values retain their list order. Meaningful semantic
changes, resolved targets, native metadata and contract-version changes change the
appropriate identity. Metadata resourceVersion, timestamps, status, managed fields and provider-generated IDs are excluded from intent/plan semantic bytes. The provider plan additionally binds a digest of referenced Kubernetes names/UIDs/generations and local mode/provider-selection authority. A reference-only change therefore changes the evaluated plan even when source generation and portable intent remain unchanged. Source generation itself remains a freshness precondition, not portable meaning.

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
public findings count (32) are bounded. Native response payloads and
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
Applied evidence advances only after acceptable bounded provider read-back and a
second local freshness check. A write acknowledgement cannot prove application.

Authorization retains its explicit owned scope/resource/policy/permission IDs.
The `hanko.sh/authorization-plan-hash` annotation is ignored. A bounded operational
journal in the backing client's `hanko.sh/resource-server-ownership` attribute
binds those references to the CR UID. It contains only a format version, owner UID,
backing client ID and owned name/ID references: **no plan, credentials or application
proof**. It is reserved from application attributes and preserved by sibling
application reconciliation. Checkpoints follow successful object creation/update;
a completed graph is recorded before the Kubernetes status patch. Losing that
patch permits recovery through the same marker and full observation, without
repeating successful provider writes. Status references alone cannot adopt an
enabled unmarked server or authorize deletion after the marker disappears.

Retired references are read back after deletion before their ownership proof is dropped; a delete acknowledgement alone cannot prove retirement.

Deletion recovers the journal even if initial status persistence failed. It removes
only owned IDs in dependency order and preserves unowned objects, including native
Keycloak defaults. Disabling Authorization Services deletes the entire graph, so
it is used only when no foreign objects remain. The journal is cleared explicitly;
repeated cleanup only verifies recorded objects are absent. Keycloak administrators
are trusted to maintain ownership markers; these markers are not signatures.

**Migration for an existing enabled resource server without this journal:** Manage
refuses it even if old status contains IDs. Review the graph and the owning CR UID
with a Keycloak administrator before assigning the operational marker, or remove
and recreate the intended aggregate after checking foreign objects. Never use an
old applied hash to authorize adoption. Keep a reviewed export before migration.
A rollback to older controller code does not understand this ownership contract;
inspect the graph and suspend management before changing controller versions.

A failed object-write response or failed ownership checkpoint may leave an
ambiguous/partially converged graph. Recorded references permit safe retries;
an unrecorded same-named object is refused and can require administrator review.
There is no exactly-once or distributed transaction guarantee.

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
JSON, findings, errors and controller status/Events/logs. The connected helper described below does not alter the live Hub payload or Continuum implementation. Bundles retain their current token-derived
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

Next: [#28](https://github.com/Alien6-Studio/hankoshell-operator/issues/28) addresses
standalone organization readiness versus configured optional projection. Provider
parity is not assumed; realm/application migration remains staged according to the
[field boundaries](provider-boundaries.md).

## Public status evidence

The existing flat `hanko.sh/v1alpha1` status fields remain compatible. Added fields
apply to `HankoResourceServer` and `HankoRole` only.

| Field | Meaning |
| --- | --- |
| `metadata.generation` | Current desired generation. |
| `observedGeneration` | Latest generation processed into status, including refusal/failure. It does not prove application. This preserves the convention used by existing controllers; Role previously had no generation field. |
| `evaluatedGeneration`, `intentHash`, `evaluatedPlanHash` | Latest fully normalized/resolved/authority/capability-evaluated attempt. A definitive semantic refusal records the generation and intent, with no evaluated plan hash. Incomplete reference/provider lookup leaves the prior evaluation intact. |
| `appliedGeneration`, `appliedPlanHash` | Latest Manage plan with successful execution, acceptable bounded read-back and freshness validation. Failed attempts retain prior proof. Observe clears these fields and never claims application. |
| `observedStateHash` | Version/domain/purpose-separated digest of an explicit private provider-semantic projection. It is neither an intent hash nor an authorization credential. |
| `observationGeneration`, `observationPlanHash` | Input generation/plan associated with the latest successful bounded observation. A failed read preserves that historical observation. |
| `observationComplete`, `driftState` | Coverage and comparison for that observation: `InSync`, `Drifted`, or `Unknown`. Partial coverage may prove drift but cannot prove equality. |
| `contractVersion`, `backendKind`, `capabilities`, `capabilityEvidence` | Domain contract, backend and static adapter qualification. These do not discover the installed Keycloak version at runtime. |
| `findings` | Bounded typed lossless/lossy/unsupported findings. Read-only native findings are distinct from rejected desired semantics. |

`Synced` is true only for a complete matching observation; Manage additionally
requires owned, proven execution. `ObservationSucceeded=True` can coexist with
`Synced=False/DriftDetected`: reading successfully does not mean equality. Partial
coverage reports `ObservationIncomplete`. `phase=Ready` requires synchronized
coverage; Observe drift/incomplete coverage has `phase=Error` while its successful
observation remains explicit. Each condition carries its processed generation.
Existing readiness consumers therefore cannot accept drift as Ready.

Old resource-server `appliedPlanHash` values written after HTTP acknowledgement
have no `appliedGeneration` and are cleared on the next processed attempt. They
are not silently promoted into proof. A successful Manage read-back establishes
new applied evidence. Owned references remain separate operational bookkeeping.

| Outcome | Processed | Evaluated | Applied | Observation / synchronization |
| --- | --- | --- | --- | --- |
| Invalid/missing/deleting references, failed lookup or authority preflight | Current | Prior evidence retained | Prior proof retained | No new observation; failure condition. |
| Unsupported/lossy desired semantics | Current | Current intent, no compiled plan | Prior proof retained | `Unsupported`/`UnsupportedCapability`, no provider writes. |
| Stale local inputs before execution | Attempted generation | Compiled attempt retained | Prior proof retained | `StalePlan`, bounded retry, no provider mutation. |
| Provider write failure | Current | Current compiled plan | Prior proof retained | Safe error; checkpointed ownership can recover partial progress. |
| Read-back failure/incomplete coverage | Current | Current compiled plan | Prior proof retained | Historical observation retained on failed read; incomplete successful read is explicit. |
| Manage read-back still differs | Current | Current compiled plan | Prior proof retained | New observation, `DriftDetected`; not Ready. |
| Kubernetes status patch fails | Last persisted status unchanged | Last persisted status unchanged | Last persisted status unchanged | Retry recompiles, checks ownership and reads provider; a matching graph needs no new writes. |
| Observe drift | Current | Current compiled plan | Cleared | New successful observation, drift visible, zero provider writes. |
| Manage repairs drift | Current | Current compiled plan | Current only after matching read-back | New complete observation and `Synced=True/Reconciled`. |

For all failure rows, Observe clears applied claims once status can be persisted.
Historical hashes must be read with their associated generations/plan identities,
not taken as a claim about the current desired state or current attempt.

## Observation normalization and bounds

Authorization reads enabled state, scope descriptions, resource names/display
names/types/URIs/scope bindings, typed role/client policies (logic, strategy,
required-role semantics and principals), typed scope permissions and associated
policy/resource/scope bindings, and owned-object presence. Set-valued fields are
sorted/deduplicated. Provider IDs resolve relationships privately but do not enter
observation identity. Known absent logic normalizes to Keycloak's `POSITIVE`;
missing decision strategy or unidentified principal/binding yields incomplete
coverage rather than assuming `AFFIRMATIVE` equality. Unmanaged native objects
produce kind-only read-only findings; the full native inventory is not exported.

Role observations include presence, owned/unmarked/foreign marker class,
description, composite flag, direct declared realm-role membership, effective
realm-role closure and supported native attributes. Extra composites are additive
and do not automatically imply drift. Attribute values preserve list order.
Credential-shaped keys are excluded and report incomplete coverage. Client-role
composites cannot be fully identified under this realm-role observation mapping;
they produce a read-only coverage finding, without inventing client identities or
extra grants. Effective authority is checked again before application is reported.

Public findings are sorted/deduplicated, capped at 32, with kind/code 64, name 255
and message 256 characters. Overflow adds a fixed read-only summary. Ownership
references are never truncated: at most 64 scopes, 64 resources, 256 policies and
128 permissions, names at most 512 bytes and IDs 128 bytes. Journal JSON is at
most 512 KiB. Creating new names alongside stale references must fit that budget;
prune old objects in a prior reconcile when necessary. Observation responses retain
HTTP byte limits. Authorization collections are read in explicit 100-object pages,
up to 1024 objects per collection, including native objects. An oversized page or
budget overflow fails with `ObservationIncomplete`; partial collections
cannot prove equality, object absence or permission to disable a backing graph.
Role traversal caps at 512 visited roles and 1024 pending nodes.
Canonical observations stay private; public status contains only hashes, coverage
and findings, not graph arrays, raw representations or executable plans.

## Connected evidence

`supervision.BuildIAMEvidence` emits a deterministic DTO for both migrated kinds:
resource identity, desired/processed/evaluated/applied generations, contract/backend,
validated hashes, observation association/coverage, drift and finding counts. It
sorts entries and caps output at 64 resources with an explicit truncation flag.
It excludes native attributes, ownership/provider IDs, timestamps, condition
messages, raw provider data and executable plans. Unknown digest/version/backend
strings are discarded; this remains untrusted descriptive evidence, never authority.

The current supervision heartbeat schema is duplicated in the Hub store. No
receiving-Hub qualification exists for the new IAM DTO, so live transport activation
is deferred. The tested helper is available without Hub installation. The existing
HMAC bundle authentication and Continuum transport/enforcement remain unchanged.
