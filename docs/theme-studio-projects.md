# Declarative Theme Studio project builds

The Studio source integration adds optional `projectGzip` and `projectSHA256` to
HankoTheme. Existing appearance-token and precompiled-artifact paths remain
available. Project mode requires a compatible, approved compiler image; it must
not silently fall back to the appearance-only builder.

The source is a gzip-compressed `hanko.theme-studio.project/v1` JSON document,
base64 encoded. Its SHA-256 covers the exact uncompressed bytes. Kubernetes input
is bounded to 900,000 base64 characters; controller decompression is bounded to
40 MiB. Both fields must be present together and cannot accompany legacy design
tokens or artifactSHA256. Full page validation happens in the reviewed compiler.
Plugin declarations never install executable code from a project.

The controller verifies its existing image approval and signature policy before
creating the immutable source ConfigMap and Job. The input mount is read-only,
separate from the provider output PVC. The container receives no service-account
token. Source ownership transfers from the Theme to the verified Job, allowing
Job TTL and Kubernetes garbage collection to clean it up without new ConfigMap
delete permission. Source digest, immutable bytes, ownership and Job execution
contract are checked before an existing Job is trusted.

The normal provider installation, Keycloak rollout observation and current
observedGeneration determine readiness. A build receipt must match the submitted
project digest before an API declares it installed. Compilation does not imply
that a realm has selected the theme.

## Realm email themes

`HankoRealm.spec.emailTheme` is optional: omission leaves the native Keycloak
setting unmanaged; an explicit empty string restores the default. It uses the
same managed-theme readiness and deletion protection as loginTheme. Client login
overrides remain `HankoApplication.spec.theme`; email selection belongs to the
realm. The Dashboard API snapshots live previous values and uses guarded
resourceVersion updates for assignment and rollback.

## Rollout and recovery

Install compatible CRDs/controller before accepting project requests. Submit API
writes with strict field validation so older schemas reject unknown source fields.
Publish and approve the corresponding compiler image by exact digest using the
existing supply-chain process. Keep all admission and verifier policies enabled.

Before downgrading, stop new builds, finish active Jobs and restore/detach their
realm and client assignments, including email. Preserve any installed JAR still
in use. Follow normal finalizer handling; do not forge installation state or drop
project fields from active requests through an old schema.

## Qualification scope, 2026-10-30

Controller tests cover source mismatch, conflicting build modes, immutable input,
Job ownership/collection, read-only mounts and absence of API credentials. Native
client tests cover omitted, explicit and cleared email themes. Realm tests cover
email readiness and deletion protection. The API and builder repositories also
exercise actual offline worker packaging, native Keycloak authentication and
local SMTP rendering. The installed Kubernetes build/rollout/assignment lifecycle
and the full supported provider matrix remain release gates for this addition.

The reviewed security inventory changes only the three bounded fields and two
schema hashes. The six rendered RBAC/admission profiles are identical. The
updated Go reference is a development fixture; no published baseline is replaced.
