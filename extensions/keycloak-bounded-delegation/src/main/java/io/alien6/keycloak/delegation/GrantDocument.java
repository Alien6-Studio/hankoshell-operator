/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/** Administrative configuration, not a token claim or an approval supplied by a caller. */
public record GrantDocument(int version, String phase, String ownerUID, String revision,
                            String realmID, Binding audience, List<Grant> grants, List<Binding> retiredActors) {
    public static final String ATTRIBUTE = "oauth.bounded-delegation.v1";
    public static final String ACTOR_ATTRIBUTE = "oauth.bounded-delegation.actor.v1";
    public static final String REALM_ATTRIBUTE = "oauth.bounded-delegation.profile";
    private static final ObjectMapper JSON = JsonMapper.builder(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(16).maxStringLength(8192)
                    .maxNumberLength(12).build()).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                    DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
            .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS).build();

    public record Binding(String id, String attribute, String value) {
        public Binding {
            name(id); name(attribute); name(value);
        }
        public ClientModel resolve(KeycloakSession session, RealmModel realm) {
            ClientModel client = session.clients().getClientById(realm, id);
            if (client == null || !client.isEnabled() || !value.equals(client.getAttribute(attribute))
                    || !"openid-connect".equals(client.getProtocol())) throw new Bounds.Rejected("stale_identity");
            return client;
        }
    }

    public record Condition(String kind, String id, String attribute, String value) {
        public Condition {
            if (kind == null || !Set.of("client", "role", "group").contains(kind)) throw new IllegalArgumentException("grant_condition");
            GrantDocument.name(id);
            if (!kind.equals("role")) { GrantDocument.name(attribute); GrantDocument.name(value); }
        }
        boolean allows(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user) {
            return switch (kind) {
                case "client" -> new Binding(id, attribute, value).resolve(session, realm).equals(client);
                case "role" -> realm.getRoleById(id) != null && user.hasRole(realm.getRoleById(id));
                case "group" -> {
                    var group = session.groups().getGroupById(realm, id);
                    yield group != null && value.equals(group.getFirstAttribute(attribute))
                            && user.getGroupsStream().limit(1025).anyMatch(member -> member.getId().equals(id));
                }
                default -> false;
            };
        }
    }

    public record Grant(String name, Binding actor, Binding subject, Authority authority,
                        List<Condition> conditions, int maxDepth, int maxTTLSeconds) {
        public Grant {
            GrantDocument.name(name);
            if (actor == null || subject == null || actor.id.equals(subject.id)) throw new IllegalArgumentException("grant_identity");
            if (conditions == null || conditions.isEmpty() || conditions.size() > 128) throw new IllegalArgumentException("grant_conditions");
            conditions = List.copyOf(conditions);
            new Bounds.Grant(authority, maxDepth, maxTTLSeconds);
            // This deployment profile matches the operator's reviewed admission contract.
            // The pure kernel has no Hanko-specific depth/lifetime ceiling.
            if (maxDepth > 4 || maxTTLSeconds > 600 || authority.permissions().isEmpty()) throw new IllegalArgumentException("grant_profile");
        }
        public Bounds.Grant bounds() { return new Bounds.Grant(authority, maxDepth, maxTTLSeconds); }
        public void authorize(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user) {
            if (conditions.stream().noneMatch(condition -> condition.allows(session, realm, client, user))) {
                throw new Bounds.Rejected("grant_principal_denied");
            }
        }
    }

    public GrantDocument {
        if (version != 1 || phase == null || !Set.of("Prepared", "Applied", "Verified", "Committed").contains(phase)) {
            throw new IllegalArgumentException("grant_version_or_phase");
        }
        name(ownerUID); name(revision); name(realmID);
        if (audience == null || grants == null || grants.isEmpty() || grants.size() > 128
                || grants.stream().map(Grant::name).distinct().count() != grants.size()) throw new IllegalArgumentException("grant_inventory");
        grants = List.copyOf(grants);
        if (retiredActors == null) retiredActors = List.of();
        if (retiredActors.size() > 128) throw new IllegalArgumentException("grant_inventory");
        retiredActors = List.copyOf(retiredActors);
    }

    public static GrantDocument parse(String value) {
        if (value == null || value.length() > 128 * 1024) throw new Bounds.Rejected("grant_unavailable");
        try { return JSON.readValue(value, GrantDocument.class); }
        catch (IOException | IllegalArgumentException ex) { throw new Bounds.Rejected("grant_invalid"); }
    }

    private static void name(String value) {
        if (value == null || value.isBlank() || value.length() > 512 || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("grant_name");
        }
    }
}
