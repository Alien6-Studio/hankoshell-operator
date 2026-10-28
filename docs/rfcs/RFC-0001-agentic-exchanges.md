# RFC-AGENT-AUTH-001 — Bounded authority for agent-to-agent and MCP exchanges

| Field | Value |
| --- | --- |
| Status | **Proposed** — design and qualification only; no new production feature claimed |
| Revision | `0.1.0-draft.1` |
| Date | 2026-10-27 |
| Scope | Single Keycloak realm; software-to-software authority; A2A 1.0; MCP HTTP tools |
| Hanko review | [Alien6-Studio/hankoshell-operator#165](https://github.com/Alien6-Studio/hankoshell-operator/issues/165) |
| Provider review | [Alien6-Studio/keycloak-bounded-delegation#12](https://github.com/Alien6-Studio/keycloak-bounded-delegation/issues/12) |
| Repository paths | Same file under `docs/rfcs/RFC-0001-agentic-exchanges.md` in both repositories |

**Shared contract:** this RFC is deliberately mirrored in both repositories. Changes to normative sections require two coordinated reviews. Neither merge alone activates the proposed feature. The two implementations remain separate, with an immutable consumer pin and their own qualification evidence.

## 1. Problem and motivation

An agent A can delegate a task to agent B over A2A; B can call a protected MCP tool, which may call a downstream API. A2A describes tasks and capabilities; MCP describes tool invocation. Neither alone proves that B is authorized to exercise *a subset of A's authority* on a specific resource for a specific task. An Agent Card, tool description, LLM response, task identifier or client-supplied metadata is not an authorization grant.

Today the Hanko operator can declare `HankoApplication` / `HankoServiceAccount` identities and `HankoResourceServer` resource/scope grants with `spec.permissions[].delegation`. The dedicated Keycloak extension supports **experimental `software-v1`**: authenticated software actor and subject, one resource-server audience, the intersection of their existing effective UMA rights and the declared grant, limited TTL and delegation depth, and actor-token replay protection. These mechanisms are real but **do not prove task-specific authorization or A2A/MCP interoperability on their own**.

The first goal is an end-to-end demonstration of **bounded authority at a real MCP resource**, not another agent runtime or a new LLM framework. The longer-term goal is an opt-in task-bound authorization extension, provided it survives threat-model review and native multi-node qualification.

## 2. Normative terms

- **Subject (A):** authenticated software principal providing the original delegable authority; not an arbitrary user name in an A2A message.
- **Actor (B):** independently authenticated software principal exercising attenuated authority; the requester, actor, subject and resource audience remain distinct.
- **A2A recipient:** the independently protected endpoint accepting a task. It does not become the token issuer.
- **MCP resource server:** an OAuth-protected receiver of MCP tool invocations with its own exact audience.
- **Trusted exchange adapter:** application-side mediator that authenticates the principals, handles their tokens outside the LLM context and invokes the authorized Keycloak exchange. Its runtime location is **not** the Hanko reconciliation loop.
- **Task context:** trusted server-side association among a task/run, authenticated delegator and delegatee, operations, policy revision and expiry. A caller-supplied `taskId` is only a correlation hint until proven by the trusted boundary.
- **PEP:** enforcement at every protected resource API/gateway. Configuration reconciliation, a token exchange success, or a Keycloak `Ready` status does not substitute for resource-side enforcement.
- **Authority:** UMA resource/scope permission set. Agent skills and MCP tool names need an explicit, reviewed mapping to protected resources/scopes; neither is a grant by itself.

RFC 2119 terms (`MUST`, `SHOULD`, `MAY`) are requirements of this **proposal** and do not imply an implemented guarantee.

## 3. Threat model and invariants

Trusted components are the configured issuer, the independently authenticated exchange adapter, admission/policy enforcement, and resource servers. Agent code, prompt text, A2A task payloads, Agent Cards, MCP tool descriptions, file contents, remote services and caller-provided headers are untrusted inputs. A tenant may control its agent implementation and try to bypass the broker; a compromised agent may initiate calls or read its permitted workspace.

The system MUST enforce, for each issued delegated resource/scope permission:

```text
delegated_authority ⊆ subject_effective_authority
                    ∩ actor_effective_authority
                    ∩ current_declared_grant
output.audience == exact_declared_resource_server
output.exp <= min(subject.exp, actor.exp, now + max_ttl, native_exp)
chain_depth <= configured_bound
```

The current documented software-v1 defaults remain one hop and 120 seconds, with upper admission limits of four hops and 600 seconds. Bounds are not automatically proof that offline tokens can be revoked immediately.

Additional invariants:

1. Actor and subject are independently authenticated to the **same qualified realm** in the first profile; identities use immutable provider/Kubernetes ownership bindings, not reusable display names.
2. A2A ingress, MCP receiver and the downstream business API have **distinct audiences**. A token for MCP MUST NOT be passed unchanged to the downstream API. The latter authorizes a separate token/request under its own policy.
3. An agent MUST NOT receive issuer administrative rights, another tenant's credentials, reviewer authority or the ability to alter its own grants and policy revisions.
4. The service receiving the token MUST verify signature/JWKS, issuer, audience, expiry, current actor and applicable UMA resource/scopes. Nested `act` entries carry history, **never additive authority**.
5. Revoking a grant stops **new issuance and chaining** according to proven native behavior. Existing offline JWTs may remain usable until expiry. Immediate revocation requires separately proved online resource enforcement.
6. A protected task-sensitive operation MUST traverse the trusted PEP. If a direct API route bypasses task controls, task-specific authority is **not** qualified, even if software-v1 token exchange succeeds.
7. Missing provider capability, malformed policy, stale UID, unsupported context, replay, uncertain state or timeout MUST reject the protected operation, without falling back to ordinary or legacy exchange.
8. Prompts, tool results, logs, traces, CRD specs/status, task payloads and Agent Cards MUST NOT contain bearer tokens or confidential credential material.

## 4. Architecture and first end-to-end scenario

```text
Agent A (software subject)
  -- authenticated A2A task request --> Agent B ingress / trusted gateway
                                     | verifies caller and task assignment
                                     v
                         Trusted exchange adapter (outside agent)
                                     | subject evidence from A via trusted path
                                     | fresh actor evidence from B workload
                                     v
                           Keycloak + bounded exchange
                                     | resource-specific delegated JWT
                                     v
                  MCP receiver PEP (aud=MCP-resource-server)
                                     | authorize tool + UMA scope + task context
                                     v
                        Downstream API (different audience)
                        fresh authorized downstream token/credential
```

**First implementation slice (software-v1):** configure the protected A2A ingress and MCP endpoint with ordinary Hanko applications/resource servers and their separate audiences. The gateway verifies A's identity and its assignment of a task to B; it does not trust caller-supplied `taskId`. For a protected MCP call, the adapter obtains fresh actor/subject evidence under a trusted flow and invokes the existing Keycloak software-v1 exchange for **the MCP audience**. Keycloak enforces current resource grants; the MCP PEP enforces the actual tool operation. A minimal trusted gateway may maintain a task record in its own protected state, but that binding is **not present in today's delegated JWT**. Such a record is enforceable only while all protected traffic is mediated and bypass paths are demonstrably blocked.

The A2A ingress MUST not use an MCP-audience token; the MCP server MUST not accept a token issued to the A2A recipient. The adapter MUST prevent credentials from flowing through LLM messages, untrusted agent storage, generic tool parameters or observability payloads. Use synthetic service accounts and read-only resources in the initial conformance case.

**Second slice (new, not implemented):** design a separate, explicitly selected **task-bound software profile**, tentatively `task-bound-software`. A trusted issuer must bind a task authorization decision to authentic actor/subject identities, target resource, operations, expiry and policy revision. Candidate forms are (a) a signed issuer-bound, audience-limited token context or (b) protected online state coupled to an unforgeable token/reference. The team MUST threat-model both, including context spoofing, replay, confused deputy, task cancellation, approval substitution and bypass through direct APIs. The decision is **open**; do not invent a private claim and treat it as a security guarantee.

## 5. Current contracts and compatibility

- Hanko `HankoResourceServer.spec.permissions[].delegation` remains software-only: `actor` and `subject` are namespace-local `application` or `service_account` references; resource/scopes are explicitly declared. Do not create a second Hanko agent identity hierarchy or permit arbitrary Keycloak client IDs in desired state.
- Hanko owns authorization **intent**, tenant/realm/UID checks, dependency observation, readiness and declarative lifecycle. Keycloak owns authentication, native token issuance/exchange and live authorization. The MCP/A2A gateway owns **runtime task proofs, operation routing and PEP integration**.
- Keycloak's `software-v1` profile and existing tokens remain backward compatible. New task context MUST use an opt-in, capability-advertised provider path with an explicit schema/version and documented migration/rollback. No broad mapper, unchecked scope union, arbitrary token template or provider-default fallback.
- Hanko's immutable extension source/JAR pin, exact SDK compatibility, feature checks and read-back evidence remain binding. Extension installation is not activated by adding a new CRD field; unknown native provider capabilities must fail closed before writes.
- A2A/MCP protocol parsing, framework SDKs, agent discovery, prompt processing, event queues and LLM invocation do not belong in the Java Keycloak SPI or the Kubernetes operator.
- Protected Keycloak admin configuration remains with its one authorized writer. Observe/import/adoption, finalizers, atomic journals (`Prepared→Applied→Verified→Committed`), role/group composites, and rollback semantics must not be weakened.

## 6. Fan-out, lineage, replay and failure handling

Software-v1 atomically consumes an **actor-token JTI** for issuance; using the same actor token on two parallel branches is a **replay**, not allowed fan-out. Concurrent tasks must obtain **distinct fresh actor evidence**, and the broker must tolerate an exchange that consumed actor evidence but returned no response. Never retry the same spent actor token as if issuance were exactly-once.

Delegated outputs MAY form a bounded chain of current actor identities, but every new hop requires its own authorized grant, current permission intersection and monotonic bounds. Branches MUST NOT union their authorities; joining results is not joining permissions. If two delegated chains would need to be merged, software-v1 currently rejects that pattern: keep this restriction until a separately reviewed semantic and native test matrix exists.

Before claims of horizontal scale, prove the replay and chain evidence on at least **two real Keycloak nodes sharing the intended database/cache** under concurrent attempts, failover, restarts and partitions. A single-node success or mocked cache does not prove cluster atomicity. Define measured behavior for lost exchange acknowledgements, idempotent A2A task retries, cancellation, revoked ancestor grants, stale task authorization and held offline JWTs. Do not claim immediate revocation without an online PEP.

## 7. Responsibility matrix

| Owner | Must implement/prove | Must not implement |
| --- | --- | --- |
| Hanko operator | Portable software and API identity intent; distinct A2A/MCP resource audiences; ownership and tenant checks; provider feature gates; strict reconciliation/read-back; conformance fixture and release pin | Per-task Kubernetes objects, model orchestration, per-request token issuance, privileged credentials in status |
| Keycloak extension | Authenticated actor/subject, exact audience, native grant intersection, expiration/depth, replay/chain continuity, explicit opt-in v2 if justified, native multi-node evidence | A2A/MCP protocol endpoints, agent runtime, uncontrolled scope/role mappers, human impersonation |
| Trusted adapter / task PEP | A2A caller/task authentication; credential mediation; token-exchange orchestration; enforced task scope; MCP tool permission mapping; downstream exchange and audit | Trust arbitrary task IDs or tool descriptions; token passthrough; unrestricted direct backend routes |
| Consumers | Validate correct audience/issuer/current permissions; enforce business action; propagate failures and audit outcome | Treat `act` history as union grants; infer permission from discovery metadata |

## 8. Qualification matrix (not yet passed)

| Scenario | Expected result | Evidence location |
| --- | --- | --- |
| A→B authenticated task, B→MCP read-only tool | Read succeeds for exact resource/scope and correct audience | Hanko installed E2E + extension native token matrix |
| B attempts write or another MCP tool | Reject with no downstream side effect | Both; actual resource-side test |
| A2A token used at MCP, MCP token at downstream API | Reject; no token passthrough | Hanko end-to-end |
| Fake Agent Card, spoofed `taskId` or agent headers | Cannot grant task authority | Gateway negative tests |
| Missing/spent actor token, wrong actor or subject | Reject; no alternate token-exchange route | Extension native + Hanko |
| Revoked permission or ancestor grant; expired credentials | No new issuance; residual offline-JWT lifetime explicitly recorded | Extension + E2E |
| A→B→C bounded depth, attempted chain merge/union | Enforce declared depth; never union grants | Extension native |
| 1/10/100 concurrent exchanges, failover between Keycloak nodes | Exactly documented issuance/replay behavior; measured p50/p95, error budget, recovered state | Extension cluster suite, no universal performance claim |
| Pod restart, Keycloak outage, broker restart/partition, stale operator plan | Fail closed and recover without silently widening grants | Hanko installed fault matrix |
| Existing software-v1 config and unrelated Keycloak clients | No regression, no new activation without opt-in | Both regression suites |

Qualified evidence MUST link source commit, Keycloak SDK/cluster/cache versions, Kubernetes chart/image and policy revision where applicable. Use real TLS-protected endpoints and real signed tokens for the security-critical path; mocks are permitted only for unrelated application behavior.

## 9. Proposed delivery gates and sequencing

1. **RFC/design gate:** joint ownership of this RFC, A2A and MCP resource/audience map, gateway trust boundaries, attacker capabilities, error semantics and rejected alternatives. Current implementations remain unchanged.
2. **Interop gate:** one real A2A software task and one real MCP tool using existing software-v1 tokens with **mandatory** gateway/PEP checks. Document expressly what is *not* task-cryptographically bound.
3. **Provider safety gate:** multi-node atomic replay and chain-state behavior, stale/expired context, failover and quota/load characterization under immutable qualification artifacts.
4. **Task-bound authority gate:** separately versioned provider capability, issuer-validated context, explicit consent/approval semantics **if ever in scope**, migration/rollback and complete denial/bypass matrix.
5. **Consumer scale gate:** installed Kubernetes/KC matrix, repeated child/fan-out tasks, A2A/MCP interoperability across supported SDKs, privacy-safe telemetry and operational evidence.

Each gate requires code and allowed/denied/failure-path tests to close its implementation issue. Documentation alone does not qualify a product capability.

## 10. Explicitly out of scope for this RFC

Human-on-behalf-of/consent, direct Entra-to-Keycloak token exchange, cross-realm/cross-organization trust, a new universal agent directory, A2A task scheduler, LLM evaluation, arbitrary executable skill discovery, semantic prompt authorization, gateway product launch, multi-cloud federation and native upstream Keycloak acceptance. Each would require a separate reviewed contract and tests.

## 11. Open questions for joint review

1. Where is the trusted A2A task assignment proven, and how do we make direct MCP bypass impossible without requiring a proprietary deployment topology?
2. Does a task-bound v2 need an issuer-signed context claim, token binding/sender constraint or an online authorization record? What are the revocation, scaling and privacy costs?
3. How should a broker authorize concurrent child branches while retaining software-v1 actor-JTI single-use?
4. Which exact receiver proof and error semantics are required if an MCP gateway brokers a token to an independent business API?
5. Which Keycloak cluster topology supports the required single-use/chain persistence guarantees with measured behavior during partitions?

## 12. References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html); specifically `act` / `may_act` and audience/resource semantics.
- [A2A protocol 1.0 specification](https://a2a-protocol.org/v1.0.0/specification/), including authentication and Agent Cards.
- [MCP authorization specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), including audience validation and no token passthrough.
- [Hanko: Delegation and agent authority](https://github.com/Alien6-Studio/hankoshell-operator/blob/main/docs/architecture/delegation-and-agent-identity.md).
- [Keycloak extension: software-v1 architecture](https://github.com/Alien6-Studio/keycloak-bounded-delegation/blob/main/docs/architecture.md), native qualification and cluster-readiness limits.

**Review decision requested:** agree to a protocol-neutral bounded authority architecture and its evidence gates. No automatic approval of a new Keycloak profile or Kubernetes API surface is requested.
