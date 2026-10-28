# A2A and MCP bounded authority fixture

`identities.yaml` uses the existing experimental `v1alpha1` APIs and
`bounded-delegation/software-v1`. The installed qualification runner loads it in
its disposable watched namespace. It is synthetic configuration, without real
credentials, tenant identifiers or infrastructure.

| Receiver | Audience | Resource and operation |
| --- | --- | --- |
| Agent B ingress | `agent-b-ingress` | `tasks#invoke`, authenticated Agent A |
| MCP | `agent-mcp-api` | `invoice#read`, B acting for A |
| Business API | `agent-business-api` | independent B `invoice#read` |

The trusted fixture authenticates A's A2A 1.0 `POST /message:send`, creates its
own assignment, obtains fresh A/B UMA evidence and performs the actual native
Keycloak bounded exchange. Credentials are mounted only in the trusted workload.
Message text, Agent Cards, tool descriptions and supplied task IDs cannot select
an identity, target, grant or operation. There is one statically mapped MCP tool,
`read_invoice`, using MCP HTTP JSON-RPC 2025-11-25.

The MCP PEP validates signed issuer/audience/expiry, current actor and subject,
resource/scope, and its private gateway assignment. Backend access obtains a
different audience token from native authorization. Neither protected receiver
accepts a direct request without the gateway's private proof. Deployment owners
must additionally restrict network access and keep the gateway memory and
credential mounts inaccessible to agents.

Default software-v1 JWTs contain no cryptographic task binding. Those checks depend
on the mandatory gateway and its in-memory record. Restart loses outstanding
assignments and refuses them. A lost exchange response is never retried with the
same actor token. Each new task obtains fresh evidence; replay and native policy
revocation remain Keycloak obligations. Offline JWTs retain their bounded expiry.

This is a qualification fixture, not a supported production agent gateway or a
complete A2A/MCP implementation. Streaming, push notifications, arbitrary tools,
interactive/human authorization and federation are outside
its advertised interface. Full installed and independent Keycloak cluster
qualification remain required before release claims.

The same installed runner separately enables `delegation.taskAuthorization:
required`, provisions a distinct trusted authority and authenticates the MCP
recipient independently. It registers exact-input approvals, verifies the native
signed context and calls the issuer's online recipient decision before the tool.
Cancellation, unknown/reused approval, authority outage and controlled withdrawal/
opt-out have dedicated cases. See the [contract](../../docs/rfcs/RFC-0002-task-authorization.md)
for deliberate native setup, required database state and rollback sequencing.

Decision telemetry uses a typed allowlist, server-created trace context and
per-process opaque identity correlators. The example exports OTLP JSON over
verified TLS to a disposable protocol sink. Spans describe gateway-observed
decisions around native requests; native Keycloak server tracing is configured
separately. Collector loss denies the operation and records incomplete coverage.
Parent-span records expire after five minutes and are bounded to 1024 traces;
Pod log retention is the cluster administrator's responsibility. No reference,
approval, token/hash, prompt or raw identity belongs in the trace schema.

A separately forked client attempting to inherit task/trace authority is denied
and receives a separate untrusted trace. General child-agent execution remains
unobserved and the report explicitly marks that coverage incomplete. Correlation
does not grant a child any business permission.
