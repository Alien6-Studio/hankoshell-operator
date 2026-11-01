# Declarative Theme Studio project builds

## Consumer contract in 1.2.0

Operator 1.2.0 introduces these additive fields. Operator 1.1.0 and earlier do
not implement project builds or realm email-theme management. A consuming
platform must select one complete operator version: matching controller image,
chart and CRDs. A newer API alone cannot add these capabilities to an older
installation.

The compiler must implement `hanko.theme-studio.project/v1` and the
`build-project` command with `--project-sha256`, `--name`, `--jar-name` and
`--out`. HankoShell Theme Builder 0.1.2 implements that contract. Install the
compiler when producing its immutable image; Jobs never download a package or
follow a source branch. Public registry or private registry distribution uses
the same source and image-approval requirements.

Use the published OCI chart at the selected exact version, or build the reviewed
source for a private installation. Keep images pinned to their independently
approved digest. A source candidate is not evidence of a published or approved
image. Publication requires the matching source and final-image delivery gates.

## Project input and readiness

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
contract are checked before an existing Job is trusted for installation. Once
the current generation is installed, collection of its source does not invalidate
readiness or trigger a new build, even if the cache still sees the completed Job.
An existing Job's execution contract and image approval remain checked.

The normal provider installation, Keycloak rollout observation and current
observedGeneration determine readiness. A build receipt must match the submitted
project digest before an API declares it installed. Compilation does not imply
that a realm has selected the theme.

The Deployment's `keycloak` container must mount the root of `keycloakPVC` at
`/opt/keycloak/providers/`, without `subPath` or `subPathExpr`. Keycloak may read
that mount read-only; the separate build Job writes the same PVC root. The
controller checks this binding before starting a build and again before
installation, so a Deployment change during compilation cannot produce a false
`Ready` result. Other containers' mounts do not establish this binding.

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

Before upgrading an existing theme installation, verify the provider mount above
and use non-optimized Keycloak startup for this live provider-PVC workflow.
An incompatible Deployment reports `UnsupportedThemeRuntime` without a new build
or restart. Correct its container name, claim and mount, or startup arguments;
the controller retries the same desired theme and observes the rollout normally.

Before downgrading, stop new builds, finish active Jobs and restore/detach their
realm and client assignments, including email. Preserve any installed JAR still
in use. Follow normal finalizer handling; do not forge installation state or drop
project fields from active requests through an old schema.

## Qualification scope

Controller tests cover source mismatch, conflicting build modes, immutable input,
Job ownership/collection, read-only mounts and absence of API credentials. The
project reconciliation test follows construction, a changed provider claim,
configuration repair, rollout readiness and post-installation source/Job
collection in either observed order without rebuilding. Runtime tests reject
unsupported startup and provider mounts before creating a build or source object. Native
client tests cover omitted, explicit and cleared email themes. Realm tests cover
email readiness and deletion protection. The API and builder repositories also
exercise actual offline worker packaging, native Keycloak authentication and
local SMTP rendering. The installed Kubernetes build/rollout/assignment lifecycle
and the full supported provider matrix remain release gates for this addition.

The reviewed security inventory changes only the three bounded fields and two
schema hashes. The six rendered RBAC/admission profiles are identical. The
updated Go reference is a development fixture; no published baseline is replaced.
