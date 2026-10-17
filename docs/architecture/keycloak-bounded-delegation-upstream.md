# Proposed Keycloak contribution: bounded delegated token exchange

Status: local discussion draft, not submitted or accepted by Keycloak.
The user authorized developing a dedicated extension on 2026-10-17. This is an
additional deployment component; the operator still refuses delegation on an
unextended provider. No production capability is enabled by this document.

## Proposed discussion

**Title:** Opt-in authority, depth and lifetime bounds for delegated token exchange

Keycloak already implements RFC 8693 delegation in the 26.8 preview. We propose
optional restrictions on delegated exchanges, building on that implementation
rather than introducing another identity protocol or replacing its consent flow.

Our use case is a software actor exercising a deliberately limited part of a
subject's authority against one resource server. An administrator needs to bound
the resulting authority, number of delegation hops and token lifetime. These are
application security requirements, not guarantees automatically supplied by RFC
8693 or defects implied by a successful standards-compliant exchange.

For an explicitly selected policy, the desired invariants are:

```text
output authority ⊆ actor token ∩ subject token ∩ current actor/subject grants ∩ policy
output audience ⊆ declared audience
output expiry ≤ min(actor expiry, subject expiry, native expiry, now + policy TTL)
output depth ≤ policy depth limit and all applicable inherited limits
```

Authority needs separate treatment for OAuth scopes, realm roles, client roles
and Authorization Services resource/scope permissions. A realm-role name alone
does not represent its effective composite closure. Nested historical `act`
claims supply audit context, never authority to union into a new token.

The opt-in policy must not raise realm, client or session lifetimes. It must
reject missing, invalid, expired or foreign-issuer inputs, undeclared audiences,
over-limit chains and excess authority. Any route to standard exchange or a
different requester must preserve these restrictions rather than laundering
delegation history out of a token. Tokens remain Keycloak-issued access tokens
with RFC 8693 `act`; no new token format or external token broker is proposed.

Native consent and FGAP remain the authority for human delegation. The Hanko
software-only adapter does not acquire human credentials, impersonate a user or
claim to qualify human delegation. Its explicit administrative grant between
service accounts is a separate integration concern, not a replacement for native
human consent proposed upstream.

## Reproducible baseline

The operator repository already contains real HTTPS tests using digest-pinned
Keycloak images, verified JWKS signatures and disposable credentials. On the
unchanged `c864346c825af2d36f9912e614bd4f7eeb33bd65` source, the focused
characterization was rerun on 2026-10-17:

| Version/profile | Result | Meaning |
| --- | --- | --- |
| 26.7.5 standard | 26 named tests pass; unavailable preview explicitly skipped | Standard exchange is not bounded delegation |
| 26.8.0 standard + delegation preview | 41 named tests pass | Actor binding exists in the preview, but the additional policy invariants are not established |

These passing tests intentionally demonstrate counterexamples to the stronger
contract; they are not a positive qualification of bounded delegation. They
cover scope addition, composite expansion, input replay, depth, expiration and
permission withdrawal. See [the authority contract](delegation-and-agent-identity.md)
for the complete matrix and exact upstream source revisions.

The native `may-act` client policy validates the `may_act` claim when that claim
is issued. It does not inspect an already authorized input during an exchange
whose output carries `act`, and it does not supply the proposed intersection,
depth or expiry restrictions. This scope is visible in the exact
[26.8 executor source](https://github.com/keycloak/keycloak/blob/4246609cf2024c85016d3fb1254c3d2533367c31/services/src/main/java/org/keycloak/services/clientpolicy/executor/RejectMayActClaimExecutor.java)
and the [official token-exchange guide](https://www.keycloak.org/securing-apps/token-exchange).
This source review is distinct from runtime qualification of that optional policy.

## Candidate implementation and review boundaries

The prototype lives in `extensions/keycloak-bounded-delegation`. A pure Java
policy kernel has no Kubernetes, Hanko CRD, controller or Hub dependency. A
version-specific SPI bridge must validate native tokens, enforce live provider
authority and bound the token before signing. It must never trust client-supplied
claims as administrative approval. Unrelated ordinary exchanges need explicit
regression tests, including installations without the extension.

The operator adapter separately owns namespace/realm/tenant resolution, Kubernetes
UID freshness, least-privilege administration, ownership conflicts, non-secret
Prepared/Applied/Verified/Committed recovery and capability/plan identity.
Those Hanko concerns are not part of the proposed Keycloak feature.

A private SPI prototype on our supported 26.7.5/26.8.0 matrix is not automatically
an upstream patch. An upstream contribution must target Keycloak's current main
branch, use its native test framework and agree on public configuration and
extension points with maintainers. Backport support remains our responsibility
unless the project explicitly agrees otherwise.

## Questions for maintainers

- Should the restrictions be a client-policy executor, delegation-provider
  settings, or a smaller common token-exchange policy hook?
- Which authority dimensions can be supported completely in a first change,
  including Authorization Services permission intersection and composite drift?
- How should the server retain and enforce inherited chain limits? An `act`
  history alone does not prove that an earlier grant allowed a later hop.
- Should actor single-use/replay prevention be a separate optional policy?
  RFC 8693 permits input reuse; our software profile requires an atomic shared
  server-side check. Revocation of future issuance and offline token expiry
  need separate, explicit documentation.
- What is the preferred test coverage for client policies, native consent,
  clustering, grant withdrawal and alternative exchange routes?

## Contribution sequence

Follow the [Keycloak contribution guide](https://github.com/keycloak/keycloak/blob/main/CONTRIBUTING.md):
discuss this enhancement first, agree on its scope, associate an issue, then
submit focused patches with functional tests and documentation. The existing
[delegation feature tracker](https://github.com/keycloak/keycloak/issues/38279)
and [exchange implementation task](https://github.com/keycloak/keycloak/issues/50204)
provide context; check their current status before opening a duplicate.

Keep the proposal public and generic, without credentials, private token
responses, customer data or unconfirmed audit candidates. Do not present stronger
application requirements as an upstream vulnerability report. Any independently
confirmed vulnerability follows the project's private disclosure process.

Commits require DCO sign-off and Apache-2.0-compatible code. The future PR must
disclose use of an AI coding agent, as required by the contribution guide. The
submitting maintainer remains responsible for understanding the changes,
answering review and maintaining the contribution. This local draft sends no
message and creates no issue, discussion or upstream PR.
