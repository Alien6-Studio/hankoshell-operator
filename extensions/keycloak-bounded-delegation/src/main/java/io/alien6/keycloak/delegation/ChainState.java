/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;

/** Private, expiring server evidence. No token, token hash or human inventory is retained. */
record ChainState(int depth, int maxDepth, int maxTTLSeconds, Map<String, String> policies) {
    ChainState {
        if (depth < 0 || depth > 4 || maxDepth < 1 || maxDepth > 4 || maxTTLSeconds < 1 || maxTTLSeconds > 600
                || policies == null || policies.size() > 8) throw new Bounds.Rejected("chain_invalid");
        policies = Map.copyOf(policies);
    }

    static ChainState read(KeycloakSession session, RealmModel realm, AccessToken token) {
        Object act = token.getOtherClaims().get("act");
        if (act == null) return new ChainState(0, 4, 600, Map.of());
        Map<String, String> evidence = session.singleUseObjects().get(key(realm, "issued", token.getId()));
        if (evidence == null) throw new Bounds.Rejected("chain_unqualified");
        try {
            int depth = Integer.parseInt(evidence.get("depth"));
            Map<String, String> policies = new HashMap<>(evidence);
            policies.keySet().removeAll(java.util.Set.of("depth", "maxDepth", "maxTTLSeconds"));
            ChainState state = new ChainState(depth, Integer.parseInt(evidence.get("maxDepth")),
                    Integer.parseInt(evidence.get("maxTTLSeconds")), policies);
            if (actorDepth(act) != depth) throw new Bounds.Rejected("chain_invalid");
            state.policies.forEach((id, expected) -> {
                ClientModel target = session.clients().getClientById(realm, id);
                String current = target == null || !target.isEnabled() ? null : target.getAttribute(GrantDocument.ATTRIBUTE);
                if (current == null || !expected.equals(hash(current))) throw new Bounds.Rejected("chain_revoked");
                GrantDocument document = GrantDocument.parse(current);
                if (!"Committed".equals(document.phase())) throw new Bounds.Rejected("chain_revoked");
                document.audience().resolve(session, realm);
                document.grants().forEach(grant -> {
                    grant.actor().resolve(session, realm);
                    grant.subject().resolve(session, realm);
                });
            });
            return state;
        } catch (NumberFormatException | NullPointerException ex) { throw new Bounds.Rejected("chain_invalid"); }
    }

    static int actorDepth(Object value) {
        int depth = 0;
        while (value != null) {
            if (++depth > 4 || !(value instanceof Map<?, ?> actor) || !(actor.get("sub") instanceof String sub)
                    || sub.isBlank() || sub.length() > 512) throw new Bounds.Rejected("chain_invalid");
            value = actor.get("act");
        }
        return depth;
    }

    ChainState extend(ChainState other, ClientModel target, String document, GrantDocument.Grant grant) {
        if (depth > 0 && other.depth > 0) throw new Bounds.Rejected("chain_merge_unsupported");
        Map<String, String> policies = new HashMap<>(this.policies);
        policies.putAll(other.policies);
        String previous = policies.put(target.getId(), hash(document));
        if (previous != null && !previous.equals(hash(document))) throw new Bounds.Rejected("chain_revoked");
        return new ChainState(Math.max(depth, other.depth) + 1,
                Math.min(grant.maxDepth(), Math.min(maxDepth, other.maxDepth)),
                Math.min(grant.maxTTLSeconds(), Math.min(maxTTLSeconds, other.maxTTLSeconds)), policies);
    }

    void save(KeycloakSession session, RealmModel realm, AccessToken token, long now) {
        Map<String, String> values = new HashMap<>(policies);
        values.put("depth", Integer.toString(depth));
        values.put("maxDepth", Integer.toString(maxDepth));
        values.put("maxTTLSeconds", Integer.toString(maxTTLSeconds));
        String key = key(realm, "issued", token.getId());
        if (token.getExp() == null || token.getExp() <= now || !session.singleUseObjects().putIfAbsent(key, token.getExp() - now)) {
            throw new Bounds.Rejected("chain_record_unavailable");
        }
        if (!session.singleUseObjects().replace(key, values)) throw new Bounds.Rejected("chain_record_unavailable");
    }

    static void consumeActor(KeycloakSession session, RealmModel realm, AccessToken token, long now) {
        if (token.getExp() == null || token.getExp() <= now || !session.singleUseObjects()
                .putIfAbsent(key(realm, "used", token.getId()), token.getExp() - now)) throw new Bounds.Rejected("actor_replayed");
    }

    private static String key(RealmModel realm, String purpose, String id) {
        if (id == null || id.isBlank() || id.length() > 512) throw new Bounds.Rejected("token_identifier_invalid");
        return "bounded-delegation/" + realm.getId() + "/" + purpose + "/" + id;
    }

    static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }
}
