/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Token authority, never a union of historical actors or a complete user profile. */
public record Authority(Set<String> scopes, Set<String> realmRoles,
                        Map<String, Set<String>> clientRoles, Map<String, Set<String>> permissions) {
    public Authority {
        scopes = boundedSet(scopes);
        realmRoles = boundedSet(realmRoles);
        clientRoles = boundedMap(clientRoles);
        permissions = boundedMap(permissions);
    }

    public Authority intersect(Authority other) {
        return new Authority(intersect(scopes, other.scopes), intersect(realmRoles, other.realmRoles),
                intersect(clientRoles, other.clientRoles), intersect(permissions, other.permissions));
    }

    public boolean contains(Authority other) {
        return intersect(other).equals(other);
    }

    private static Map<String, Set<String>> intersect(Map<String, Set<String>> left, Map<String, Set<String>> right) {
        Map<String, Set<String>> result = new HashMap<>();
        left.forEach((key, value) -> {
            if (right.containsKey(key)) {
                Set<String> common = intersect(value, right.get(key));
                if (!common.isEmpty()) result.put(key, common);
            }
        });
        return result;
    }

    private static Set<String> intersect(Set<String> left, Set<String> right) {
        Set<String> result = new HashSet<>(left);
        result.retainAll(right);
        return result;
    }

    private static Set<String> boundedSet(Set<String> values) {
        if (values == null || values.size() > 1024) throw new IllegalArgumentException("authority_limit");
        values.forEach(Authority::boundedName);
        return Set.copyOf(values);
    }

    private static Map<String, Set<String>> boundedMap(Map<String, Set<String>> values) {
        if (values == null || values.size() > 256) throw new IllegalArgumentException("authority_limit");
        Map<String, Set<String>> result = new HashMap<>();
        values.forEach((key, value) -> {
            boundedName(key);
            Set<String> copy = boundedSet(value);
            if (!copy.isEmpty()) result.put(key, copy);
        });
        if (result.values().stream().mapToInt(Set::size).sum() > 4096) throw new IllegalArgumentException("authority_limit");
        return Map.copyOf(result);
    }

    private static void boundedName(String value) {
        if (value == null || value.isBlank() || value.length() > 512 || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("authority_name");
        }
    }
}
