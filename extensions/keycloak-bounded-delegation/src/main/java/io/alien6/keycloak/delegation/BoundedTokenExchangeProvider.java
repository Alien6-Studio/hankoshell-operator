/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.Time;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.tokenexchange.StandardTokenExchangeProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionManager;

/** Opt-in administrative software grants. Human delegation remains outside this deployment profile. */
public final class BoundedTokenExchangeProvider extends StandardTokenExchangeProvider {
    private AccessToken actor;
    private AccessToken subject;
    private Authority requested;
    private Authority currentActor;
    private Authority currentSubject;
    private GrantDocument.Grant grant;
    private ChainState chain;
    private ClientModel target;

    @Override public boolean supports(TokenExchangeContext context) {
        // Claim the whole internal access-token route before native/legacy providers.
        // Missing actor_token must not launder a delegated token through another route.
        return "software-v1".equals(context.getRealm().getAttribute(GrantDocument.REALM_ATTRIBUTE))
                && (context.getParams().getActorToken() != null || context.getParams().getSubjectToken() != null);
    }

    @Override protected Response tokenExchange() {
        try {
            validateForm();
            if (!OIDCAdvancedConfigWrapper.fromClientModel(client).isStandardTokenExchangeEnabled()
                    || client.isPublicClient() || !client.isEnabled()) throw new Bounds.Rejected("requester_disabled");
            var subjectResult = verify(params.getSubjectToken(), params.getSubjectTokenType());
            subject = subjectResult.token();
            if (params.getActorToken() == null) {
                if (client.getAttribute(GrantDocument.ACTOR_ATTRIBUTE) != null
                        || subject.getOtherClaims().get("act") != null || subject.getOtherClaims().get("may_act") != null) {
                    throw new Bounds.Rejected("actor_required");
                }
                if (!super.supports(context)) throw new Bounds.Rejected("exchange_unsupported");
                return super.tokenExchange();
            }
            var actorResult = verify(params.getActorToken(), params.getActorTokenType());
            actor = actorResult.token();
            if (subject.getConfirmation() != null || actor.getConfirmation() != null) throw new Bounds.Rejected("sender_constraint_unsupported");
            String requestedType = params.getRequestedTokenType();
            if (requestedType != null && !OAuth2Constants.ACCESS_TOKEN_TYPE.equals(requestedType)) throw new Bounds.Rejected("token_type_unsupported");
            if (actor.getSubject().equals(subject.getSubject())) throw new Bounds.Rejected("identities_equal");
            if (params.getAudience() == null || params.getAudience().size() != 1) throw new Bounds.Rejected("audience_required");
            target = session.clients().getClientByClientId(realm, params.getAudience().getFirst());
            if (target == null || !target.isEnabled()) throw new Bounds.Rejected("audience_unavailable");
            String configuration = target.getAttribute(GrantDocument.ATTRIBUTE);
            GrantDocument document = GrantDocument.parse(configuration);
            if (!"Committed".equals(document.phase()) || !realm.getId().equals(document.realmID())
                    || !document.audience().resolve(session, realm).equals(target)) throw new Bounds.Rejected("grant_unavailable");
            var candidates = document.grants().stream().filter(candidate -> candidate.actor().id().equals(client.getId())
                    && candidate.subject().id().equals(subjectResult.user().getServiceAccountClientLink())).toList();
            if (candidates.size() != 1) throw new Bounds.Rejected("grant_ambiguous_or_missing");
            grant = candidates.getFirst();
            ClientModel actorClient = grant.actor().resolve(session, realm);
            ClientModel subjectClient = grant.subject().resolve(session, realm);
            softwareIdentity(actorClient, actorResult.user(), actor);
            softwareIdentity(subjectClient, subjectResult.user(), subject);
            grant.authorize(session, realm, actorClient, actorResult.user());
            grant.authorize(session, realm, subjectClient, subjectResult.user());
            if (!actorClient.equals(client)) throw new Bounds.Rejected("actor_binding");
            var actorChain = ChainState.read(session, realm, actor);
            var subjectChain = ChainState.read(session, realm, subject);
            chain = actorChain.extend(subjectChain, target, configuration, grant);
            Authority allowed = NativeAuthority.fromToken(actor).intersect(NativeAuthority.fromToken(subject)).intersect(grant.authority());
            Set<String> scopes = params.getScope() == null ? allowed.scopes() : NativeAuthority.scopes(params.getScope());
            requested = new Authority(scopes, allowed.realmRoles(), allowed.clientRoles(), allowed.permissions());
            if (requested.permissions().isEmpty()) throw new Bounds.Rejected("authority_exceeded");
            currentActor = NativeAuthority.current(session, realm, target, actorClient, actorResult.user(), actor, grant.authority());
            currentSubject = NativeAuthority.current(session, realm, target, subjectClient, subjectResult.user(), subject, grant.authority());
            long now = Time.currentTime();
            // Validate before consuming an actor or creating a transient exchange session.
            Bounds.evaluate(new Bounds.Input(NativeAuthority.fromToken(actor), actor.getExp(), actorChain.depth()),
                    new Bounds.Input(NativeAuthority.fromToken(subject), subject.getExp(), subjectChain.depth()),
                    new Bounds.Grant(grant.authority(), chain.maxDepth(), chain.maxTTLSeconds()),
                    requested, currentActor, currentSubject, now, now + chain.maxTTLSeconds());
            validateResources();
            ChainState.consumeActor(session, realm, actor, now);
            UserSessionModel transientSession = new UserSessionManager(session).createUserSession(
                    KeycloakModelUtils.generateId(), realm, subjectResult.user(), subjectResult.user().getUsername(),
                    clientConnection.getRemoteHost(), "client_auth", false, null, null, UserSessionModel.SessionPersistenceState.TRANSIENT);
            return exchangeClientToClient(subjectResult.user(), transientSession, subject, true);
        } catch (Bounds.Rejected ex) {
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, ex.code(), Response.Status.BAD_REQUEST);
        } catch (IllegalArgumentException ex) {
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "bounded_input_invalid", Response.Status.BAD_REQUEST);
        }
    }

    private void validateForm() {
        if (formParams.size() > 24 || formParams.values().stream().anyMatch(values -> values.size() != 1
                || values.getFirst() == null || values.getFirst().length() > 64 * 1024)) throw new Bounds.Rejected("request_limit");
        for (String key : List.of("requested_subject", "requested_issuer", "subject_issuer")) {
            if (formParams.containsKey(key)) throw new Bounds.Rejected("exchange_unsupported");
        }
    }

    private AuthenticationManager.AuthResult verify(String raw, String type) {
        if (raw == null || raw.length() > 64 * 1024 || !OAuth2Constants.ACCESS_TOKEN_TYPE.equals(type)) {
            throw new Bounds.Rejected("token_invalid");
        }
        var result = AuthenticationManager.verifyIdentityToken(session, realm, session.getContext().getUri(), clientConnection,
                true, true, null, false, raw, headers, verifier -> {});
        if (result == null || result.token().getExp() == null || result.token().getExp() <= Time.currentTime()) throw new Bounds.Rejected("token_invalid");
        return result;
    }

    private void softwareIdentity(ClientModel expected, UserModel user, AccessToken token) {
        if (!expected.isServiceAccountsEnabled() || !expected.getId().equals(user.getServiceAccountClientLink())
                || !user.equals(session.users().getServiceAccount(expected)) || !user.isEnabled()
                || (!expected.getClientId().equals(token.getIssuedFor()) && token.getOtherClaims().get("act") == null)) {
            throw new Bounds.Rejected("software_identity_required");
        }
    }

    private void validateResources() {
        if (params.getResource() == null) return;
        String uri = params.getResource().getFirst();
        var authorization = session.getProvider(org.keycloak.authorization.AuthorizationProvider.class);
        var server = authorization.getStoreFactory().getResourceServerStore().findByClient(target);
        for (String id : requested.permissions().keySet()) {
            var resource = authorization.getStoreFactory().getResourceStore().findById(server, id);
            if (resource == null || !resource.getUris().contains(uri)) throw new Bounds.Rejected("resource_undeclared");
        }
    }

    @Override protected String getRequestedTokenType() {
        return grant == null ? super.getRequestedTokenType() : OAuth2Constants.ACCESS_TOKEN_TYPE;
    }

    @Override protected void validateAudience(AccessToken token, boolean strict, List<ClientModel> audiences) {
        if (grant == null) super.validateAudience(token, strict, audiences);
        else if (audiences.size() != 1 || !audiences.getFirst().equals(target)) throw new Bounds.Rejected("audience_undeclared");
    }

    @Override protected String getRequestedScope(AccessToken token, List<ClientModel> audiences) {
        return grant == null ? super.getRequestedScope(token, audiences) : String.join(" ", requested.scopes());
    }

    @Override protected void checkRequestedAudiences(TokenManager.AccessTokenResponseBuilder response) {
        if (grant == null) { super.checkRequestedAudiences(response); return; }
        AccessToken output = response.getAccessToken();
        long now = Time.currentTime();
        Bounds.Decision decision = Bounds.evaluate(new Bounds.Input(NativeAuthority.fromToken(actor), actor.getExp(), 0),
                new Bounds.Input(NativeAuthority.fromToken(subject), subject.getExp(), chain.depth() - 1),
                new Bounds.Grant(grant.authority(), chain.maxDepth(), chain.maxTTLSeconds()), requested,
                currentActor, currentSubject, now, output.getExp());
        NativeAuthority.apply(output, decision.authority());
        output.exp(decision.expiresAt());
        output.audience(target.getClientId());
        Map<String, Object> act = new HashMap<>();
        act.put("sub", actor.getSubject());
        act.put("client_id", client.getClientId());
        Object previous = actor.getOtherClaims().get("act");
        if (previous == null) previous = subject.getOtherClaims().get("act");
        if (previous != null) act.put("act", previous);
        output.setOtherClaims("act", act);
        chain.save(session, realm, output, now);
    }
}
