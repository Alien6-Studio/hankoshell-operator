# API outage and owned realm cleanup

This development qualification addresses parts of #95 and #96. It uses the
scanned exact-source image, actual chart, two replicas and real HTTPS Keycloak.
It does not qualify every journal, split brain, clock skew or production HA.

## Safe parent deletion

A managed realm waits while any namespace-local declaration references it:
Application, ServiceAccount, Issuer, Role, Organization, ResourceServer,
WorkloadTrust or Tenant. Observe declarations, terminating children and children
without finalizers still count. Remove the children explicitly, including
references that preserve foreign state, before deleting their parent realm.
This is child-first cleanup, not permission to cascade-delete arbitrary children.

The controller reads the parent and every complete dependency page directly
from the API. An unreadable, malformed or incomplete inventory refuses deletion.
After provider preflight it rechecks the parent UID, generation, deletion,
finalizer, labels and annotations immediately before the provider DELETE.
A switch to Observe or a changed tenant/connection requires a new attempt.
Kubernetes and Keycloak do not share an atomic transaction.

The expected wait reports `phase=Reconciling` on a terminating realm and
`Synced=False/DependenciesRemain`, with counts by kind instead of child names.
It retries at the existing jittered 30-second interval, without rewriting
unchanged status. API/provider failures retain error backoff. A lost provider
DELETE acknowledgement can resume against an already absent realm; it never
grants authority to remove child finalizers or delete another realm.

## Installed scenarios

The fixture creates two realms, 400 applications, 20 roles, 20 organizations
and four resource servers with four IAM workers. It replaces the leader during
initial load, then performs these additional scenarios:

- Refuse all new operator API requests, including lease renewal, for at least
  300 measured seconds. The administrator observes the real API and provider
  independently. Verify no current Ready or configuration writes after an
  in-flight drain, unchanged native state and stalled lease renewal. Sampling
  gaps above 45 seconds fail the measurement. Release the fault and require
  automatic recovery, two Ready replicas and preserved client identities.
- Request deletion of a managed realm with 222 dependents, including 200
  applications. Require the native realm to remain while resource servers,
  applications, organizations and roles are explicitly removed in order.
  Lose the acknowledgement of the accepted provider realm DELETE, replace the
  active lease holder before finalizer release, and require one accepted DELETE,
  eventual finalizer completion and all other-realm client identities preserved.

The outage affects operator API transport through an external fixture proxy;
the actual API server remains available to the administrator. Existing watch
streams may drain, but new reads/writes and lease renewal fail. No host clock
change, production failure switch, manual status reset or finalizer removal is
used to complete these installed scenarios.

```sh
make recovery-installed-test \
  OCI_ARCHIVE="$archive" OCI_EVIDENCE="$evidence" OCI_DIGEST="$digest" \
  REVISION="$revision" RECOVERY_OUTPUT="$fresh_directory" \
  KIND="$kind" KUBECTL="$kubectl" HELM="$helm" ORAS="$oras" OPENSSL="$openssl"
```

Use a clean isolated worktree at the supplied source revision. The final
`report.json` must be complete with cleanup successful; intermediate progress
does not qualify the fixture. Reports retain numeric counts, fixed assertions,
versions and hashes, excluding raw statuses, native identities and credentials.

The opt-in six-cell CI scale matrix also runs this fixture against its same
scanned OCI archive. Ordinary CI keeps its existing gates. The standalone scale
workflow adds recovery only for its `scale` profile. None of these runs qualifies
a 24-hour soak, every transaction checkpoint or production resource defaults.
