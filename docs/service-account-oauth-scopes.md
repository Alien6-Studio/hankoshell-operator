# Service-account OAuth scope attachments

`HankoServiceAccount.spec.scopes` declares native OpenID Connect client-scope
references. The operator resolves their exact names in the selected realm and
reconciles their attachments on the currently owned service-account client.
It never creates, changes or deletes shared realm scope definitions.

This increment supports ordinary Secret authentication only. Kubernetes
authentication and coordinated Secret fallback reject any explicit scope list,
including `[]`, before activation with `OAuthScopesAuthenticationUnsupported`.
Their existing workflow remains unchanged when scopes are omitted. This refusal
does not disable an already-active client or revoke its tokens; use the existing
reviewed containment or credential lifecycle workflow when revocation is needed.
Federated scope preparation must be integrated with its authentication transaction
and qualified independently before that combination can be supported.

## Intent and migration

An omitted `scopes` field leaves existing attachments unmanaged. An explicit
list is the complete desired **default** client-scope set. Every optional
attachment is removed: otherwise a client could request an undeclared optional
scope. An explicit `scopes: []` removes all default and optional attachments.
Omission relinquishes management; it does not revoke existing grants. Revoke
with an explicit empty list and confirm reconciliation before omitting the field.

This fixes earlier versions that accepted the field without applying it.
Review existing nonempty declarations before upgrading: their exact set will
become effective. Include required native claim scopes explicitly. For example:

```yaml
apiVersion: hanko.sh/v1alpha1
kind: HankoServiceAccount
metadata:
  name: artifact-reader
  namespace: identity
spec:
  realmRef: example
  clientID: artifact-reader
  scopes:
    - basic
    - service_account
    - registry:oci:artifacts:read
  tokenClaims:
    - name: artifact-api-audience
      claim: aud
      value: artifact-api
      addToAccessToken: true
      addToIDToken: false
      addToUserInfo: false
      addToIntrospection: true
```

The realm, organization assignment, API audience and resource-server enforcement
remain separate administrator decisions. A scope attachment alone does not
establish organization membership or authorize a resource server that ignores it.
The sample contains no realm-role grant or Full Scope Allowed expansion.

Scope names use the existing native preservation grammar: 1–128 ASCII letters,
digits, dots, underscores, colons or hyphens, beginning with a letter or digit.
Token-shaped `eyJ` prefixes and duplicate references are rejected. Missing,
ambiguous or non-OIDC definitions block reconciliation before client creation.

## Realm prerequisites

An authorized realm administrator must provision and review a missing OAuth
scope through the existing provider administration workflow. For example, the
native `POST /admin/realms/<realm>/client-scopes` document is:

```json
{
  "name": "registry:oci:artifacts:read",
  "protocol": "openid-connect",
  "attributes": {"include.in.token.scope": "true"}
}
```

Inspect the exact existing definition before creating anything. Duplicate
names or a definition with unexpected mappers require administrator resolution.
The example uses native OAuth scope issuance; no hardcoded `scope` claim mapper
is installed. Shared definitions and their protocol mappers remain independently
administered and may affect every attached client. Issuance must be qualified
against their actual contents, not inferred from the scope name.

The operator needs native scope and attachment reads with `view-clients` or
`manage-clients`, and attachment PUT/DELETE with `manage-clients`. It does not
need scope-definition POST/PUT/DELETE. Existing UID ownership and adoption
checks remain mandatory before every mutation.
Observe mode never changes attachments. Deleting a managed service account
removes its owned client; shared realm scopes survive.

## Confirmation, recovery and rollback

The operator resolves the complete desired set before removing old attachments,
revokes undeclared grants before adding new ones, checks current client UUID and
ownership at each mutation, and reads back exact default and optional sets.
New or recovered Kubernetes client-secret outputs are published only after those
attachments have been confirmed. A native create may have succeeded before a
later scope failure; its credential remains unpublished until reconciliation
recovers successfully. Existing active credentials retain their current native
rights during reconciliation and issued tokens remain valid until expiry.
An ambiguous network outcome is retried from the provider's current state.
Missing permission, changed ownership or mismatched read-back prevents Ready.
Concurrent external administration must not change the same owned client's
scope attachments; the provider offers no multi-request transaction.

JSON and Kubernetes unstructured serialization preserve omitted versus explicit
empty lists through typed updates. Earlier binaries use `omitempty` and can
erase explicit empty intent. Before rollback, stop consumers, revoke their
grants while this reconciler is active, confirm native attachment state, and wait
for issued access tokens to expire. Earlier binaries do not enforce declarations.
Client-secret rotation alone does not revoke already-issued access tokens.

Unit tests cover omitted/empty intent, idempotence, removal of optional grants,
missing/ambiguous definitions, stale authority, ownership loss and unconfirmed
writes. The real Keycloak `protocols` shard additionally checks signed native
client-credentials issuance, `jti`, audience, an allowed scope, rejected undeclared
scope, grant removal, read-only administrator denial and shared-scope preservation.
Run both pinned Keycloak versions before integration. The Hanko facade's
`hanko_token_use` claim remains a separate facade contract; raw Keycloak issuance
does not establish it. Source tests do not attest deployment or live readiness.
