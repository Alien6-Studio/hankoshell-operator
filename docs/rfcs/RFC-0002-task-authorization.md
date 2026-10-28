# RFC-AGENT-AUTH-002 — Issuer-controlled task authorization

| Field | Value |
| --- | --- |
| Status | Selected implementation scope for Hanko 1.1.0; experimental; full qualification pending |
| Revision | `0.1.0-draft.2` |
| Date | 2026-10-28 |
| Parent | `RFC-AGENT-AUTH-001` |
| Native work | keycloak-bounded-delegation #14–#21 |
| Consumer work | hankoshell-operator #167–#174 |

This contract is mirrored in both repositories. Task authorization is an explicit
option in 1.1.0, not a separately named “v2” product or a release prerequisite
created by naming. Existing `software-v1` remains the default.

## Trust boundary

Use an issuer-created online authorization reference. A trusted software task
authority authenticates a real assignment before registering it with Keycloak.
That authority is distinct from actor, subject and protected resource. Its
credentials belong to the trusted adapter, outside agent-writable storage.
Agent Cards, task IDs, trace IDs, prompts and tool descriptions cannot grant or
select authority. The native extension contains no A2A or MCP codec.

The existing realm selector remains `oauth.bounded-delegation.profile=software-v1`.
An administrator additionally sets `oauth.bounded-delegation.task.profile` to
`task-bound-software`, and `oauth.bounded-delegation.task.issuer` to a strict
native client `Binding` (id, attribute, value). The binding must resolve to the
same enabled confidential service account. Database-backed native single-use
state (`stateless`) is mandatory. Only the exact compiled, supported SDK enables
this option. No operator upgrade silently enables it.

## Static configuration and compatibility

Task-required audiences store an explicitly versioned journal in the existing
`oauth.bounded-delegation.v1` attribute: `version: 2`,
`profile: task-bound-software`. All existing owner, audience, revision, phase,
actor/subject, conditions, permission and TTL bindings retain their meaning.
Only `Committed` executes; task grants have one hop. Each audience uses one
profile. This wire-format discriminator makes legacy parsers reject a protected
journal; it is not a product release version. Actor guards remain in place, so
omitting actor evidence cannot select ordinary exchange.

Version-1 grant documents and seven-field software capability discovery retain
their existing wire shape. Default software delegation keeps its four-hop and
600-second ceilings. Task-bearing outputs cannot be relabelled or chained through
another profile. Additional actors/tasks require independent authorization.

Hanko adds only `spec.permissions[].delegation.taskAuthorization: required`.
Omission keeps the previous model and serialized journal. There is no task ID,
reference, token or per-task Kubernetes object. Native capability, compiler,
current references, sealed plan, journal/read-back and lifecycle checks must
agree before applying this intent. Unknown capability fields or missing bounds,
unsupported SDK/store, mixed audience profiles and multi-hop task intent refuse.

## Native protocol

All private operations require verified HTTPS and a native confidential software
access token whose sole audience is `bounded-delegation-task-context`. No realm
management role is needed. Native expiry, enabled-user/client and service-account
checks apply. Authentication and operation errors return bounded reasons without
request bodies or token material. Responses carry `Cache-Control: no-store`.

`GET bounded-delegation/task-context` is separate public discovery. Its strict
contract is `bounded-delegation/task-reference-v1`, with extension/Keycloak
versions, enabled/experimental flags, database store, online-required and
single-use-approval flags, depth one and TTL ceiling 600 seconds.

`POST .../task-context/contexts` authenticates the configured authority. A bounded,
strict JSON registration contains the native audience UUID, grant name, exact
actor/subject JTIs and service-account subjects, resource/scope permission subset,
SHA256 of the canonical reviewed operation parameters, and TTL (1–600 seconds).
The issuer resolves the current grant, identities and authority subset, and
computes the policy fingerprint itself. It generates independent unpredictable
256-bit context and approval references. Native state stores no raw token or
token hash. Context expiry is also limited by the grant; approval lives at most
30 seconds and never outlives its context.

The trusted adapter supplies the approval in the normal authenticated bounded
exchange as `task_context`, alongside actual actor and subject tokens. Before
signing, Keycloak verifies their exact JTIs/subjects, current native rights and
conditions, audience, grant fingerprint, approved permission subset, expiry and
uncancelled context. Approval and actor consumption use atomic native single-use
records. A lost response can burn evidence; retry requires fresh inputs and a new
approval. No exactly-once delivery guarantee is made.

The signed output retains `act`, one exact resource audience and attenuated UMA
permissions. Expiry is no later than both inputs, native/delegation limits and the
context. Claim `urn:alien6:bounded-delegation:task` contains only contract version
1, opaque context reference, operation parameters hash and issuer-computed policy
fingerprint. Private native evidence binds the output JTI and issued authority.

`POST .../task-context/check` authenticates the exact protected resource, separately
from the actor. The PEP first verifies JWT signature, issuer, audience, expiry,
current actor/subject and operation permissions. It sends reference, output JTI,
parameters hash, native resource UUID and scope. The issuer checks native context,
issued authority, current identity bindings, live native conditions/permissions,
policy fingerprint, cancellation and expiry. Missing/unavailable state refuses.
The PEP performs this check before each protected operation; it never substitutes
an unverified caller task ID. The MCP token is not forwarded to a downstream API.

`DELETE .../task-context/contexts/{reference}` authenticates the originating
configured authority and writes an expiring native cancellation tombstone.
Other clients cannot cancel or widen a context. An acknowledged cancellation
prevents subsequent online authorization, including across nodes with a cache
partition when the required database is available. Context state does not modify
native components, externally owned journals or actor markers.

## Execution, races and privacy

Approval is single-use for issuance. The online check is authorization, not a
once-only business execution protocol. The fixture separately consumes its local
assignment before its single tool operation. Child agents receive no inherited
authority from a tracing parent or task name. Further task/actor hops require a
new independent authorization; arbitrary child execution is not observed.

Issuance admitted concurrently with cancellation may finish; the recipient still
needs a current online allow. An online decision and the subsequent business
transaction are not atomic. An operation already admitted can finish, and an
application may need a recheck at commit. Offline JWT verification alone retains
the residual lifetime; it does not implement task cancellation. No immediate
revocation of all offline tokens or universal throughput SLA is claimed.

No raw tokens, token hashes, credentials, references, prompts, tenant/user IDs or
untrusted discovery metadata belong in public events/status/traces. Decision
telemetry uses a typed allowlist and server-created correlation IDs. Missing
collector or child-execution coverage remains explicit and cannot add authority.

## Rollout and rollback

Qualify exact source, SDK, JAR, image and topology independently in native and
consumer matrices. Native console/API continues refusing externally owned
audiences. The operator only declares durable authorization intent; it does not
become a request-time token broker or trusted task issuer.

Enable the native option deliberately, then apply task-required intent and wait
for current committed read-back. Switch the PEP to mandatory online enforcement
before trusting task-bound outputs. For downgrade or opt-out, withdraw task grants,
cancel contexts, retain actor guards, verify cleanup and wait remaining token/
context lifetimes. Remove task-required desired fields before restoring an older
schema/provider. Never automatically reinterpret a version-2 journal as version 1.
Removing the provider or enforcement changes the trust boundary.

## Required evidence

Native tests cover real signed outputs, substituted inputs/operations, forged or
reused approvals, cancellation, expiry, policy withdrawal, identity disablement,
mapper injection, fallback refusal, software regression and separate ownership.
Two-node tests cover atomic replay/approvals and cancellation under partition and
rejoin with exact database-backed state. Each supported SDK is required.

The installed consumer separately proves A2A authentication, native registration/
exchange, mandatory MCP online checks, downstream audience isolation, missing
capability, outages, lost acknowledgements, privacy and controlled opt-out.
Clean CI and final-image/release qualification remain required before publication.
