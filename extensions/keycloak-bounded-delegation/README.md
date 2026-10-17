# Experimental bounded delegation for Keycloak

This standalone Apache-2.0 Java extension implements the opt-in
`bounded-delegation/software-v1` profile. It has no Kubernetes or Hanko runtime
dependency. It is maintained here against **exactly 26.7.5 and 26.8.0**, using
Keycloak's private SPI; it is not an official Keycloak feature or a stable API.
An upstream discussion draft is [prepared separately](../../docs/architecture/keycloak-bounded-delegation-upstream.md).

## Build and qualify

Use JDK 21 or newer, Maven, Go and Docker. From the repository root:

```sh
make keycloak-extension-test KEYCLOAK_VERSION=26.7.5
make keycloak-extension-test KEYCLOAK_VERSION=26.8.0
```

Each command builds the matching SDK, runs Java kernel/parser tests, then runs
real HTTPS Keycloak/controller tests with signature-verified tokens and Go's race
detector. A missing JAR, inventory drift, failure or skip fails the dedicated gate.
The ordinary stock-provider tests remain separate. CI runs both SDKs and retains
Java reports, JAR digest/source identity and Go JUnit/results.json. No artifact is
published. `make keycloak-extension-build` builds and tests Java only.

The JAR is `target/VERSION/bounded-delegation-keycloak-VERSION.jar`. Match it to
the running Keycloak version. Copy it into the server's `providers/` directory
and run `bin/kc.sh build` when constructing the Keycloak image, following the
[Keycloak extension guide](https://www.keycloak.org/docs/26.7.5/server_development/index.html).
This operator does not silently install an extension into an existing server.

An external realm administrator must explicitly set the realm attribute
`oauth.bounded-delegation.profile=software-v1`; standard token exchange V2 must
be enabled. The delegation writer does not receive `manage-realm`. Discovery at
`/realms/REALM/bounded-delegation` reports only profile/version/limits/activation,
never grants, identities or tokens. Unselected realms continue using native
exchange. A selected realm is dedicated to this software profile: human/native
preview delegation and legacy/external exchange are not qualified in that realm.

## Contract

The authenticated actor and subject are distinct, enabled, confidential OIDC
service-account clients. The audience is one declared, enabled Authorization
Services resource server in enforcing mode. Native bindings include client UUID
and administrative ownership attribute/value; replacements do not inherit grants.
An actor marker prevents dropping `actor_token` to fall through to ordinary
exchange while its grants are installed. Existing delegated `act` tokens also
cannot take the ordinary route in a selected realm.

Administrative configuration is a strict versioned client attribute
`oauth.bounded-delegation.v1`. Only `Committed` grants execute. The operator
adapter owns its Prepared/Applied/Verified/Committed journal, explicit local
references and UID/tenant checks; those are separate from the Java policy kernel.
The bridge emits UMA resource/scope permissions and strips ambient OAuth scopes,
realm/client roles and arbitrary mapper claims. Its generic kernel can intersect
those authority dimensions independently; this does not add a new Hanko role-grant
API or authorize human consent.

At issuance, requested permissions are bounded by both signed inputs, the grant
and **current native** actor/subject policies and memberships. Output has one
explicit audience, RFC 8693 `act`, no refresh token, at most four hops and at most
600 seconds. Expiration is the minimum of both inputs, native output lifespan and
the declared/inherited TTL. Neither realm nor session lifespans are raised.
Unknown/foreign/expired inputs, permission excess, ambiguous actor/subject pairs,
chain merges and sender-constrained delegated inputs are refused. A disjoint
permission intersection issues no token.

Actor JTI consumption uses Keycloak's atomic shared single-use-object provider.
Private expiring server evidence binds issued chain depth, inherited limits and
ancestor grant configuration hashes. Raw tokens and token hashes are not stored.
Missing chain evidence refuses further exchange. Grant/owner changes invalidate
future chained issuance. Deployments require a shared, correctly configured
Keycloak cache; multi-node failover and installed Kubernetes flows still require
#71 qualification. Do not claim a local single-node fixture establishes those.

Removing an owned permission disables its native grant before releasing only its
actor ownership entries. Shared actors preserve other owners and their exchange
setting; the last owner restores the original setting. Unrelated clients and
sessions are retained. Existing offline JWTs remain usable until bounded expiry;
instant resource-side revocation is not claimed. An administrator must withdraw
grants and wait their maximum remaining token lifetime before disabling the realm
profile or uninstalling the enforcing provider. Changing that enforcement boundary
is a deployment operation, not ordinary permission revocation.

## Contribution and maintenance

The [upstream proposal](../../docs/architecture/keycloak-bounded-delegation-upstream.md)
separates optional Keycloak authority/depth/lifetime policy from Hanko ownership
and replay requirements. A contribution to current Keycloak main must use its
native test framework and agreed configuration hooks. This private-SPI adapter is
not a drop-in upstream PR. Contributions follow [Apache-2.0](../../LICENSE), DCO
sign-off, and explicit disclosure of AI agent assistance in the future PR.
