/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

/** Pure policy kernel. Callers must first authenticate both tokens and authorize the grant. */
public final class Bounds {
    public static final int MAX_CHAIN_LENGTH = 32;
    private Bounds() {}

    public record Input(Authority authority, long expiresAt, int depth) {
        public Input {
            if (authority == null || expiresAt <= 0 || depth < 0 || depth > MAX_CHAIN_LENGTH) throw new IllegalArgumentException("input_bounds");
        }
    }

    public record Grant(Authority authority, int maxDepth, int maxTTLSeconds) {
        public Grant {
            if (authority == null || maxDepth < 1 || maxDepth > MAX_CHAIN_LENGTH || maxTTLSeconds < 1) {
                throw new IllegalArgumentException("grant_bounds");
            }
        }
    }

    public record Decision(Authority authority, long expiresAt, int depth) {}

    public static final class Rejected extends RuntimeException {
        private final String code;
        public Rejected(String code) { super(code); this.code = code; }
        public String code() { return code; }
    }

    public static Decision evaluate(Input actor, Input subject, Grant grant, Authority requested,
                                    Authority currentActor, Authority currentSubject, long now, long nativeExpiration) {
        if (now <= 0 || actor == null || subject == null || grant == null || requested == null
                || currentActor == null || currentSubject == null) throw new IllegalArgumentException("policy_input");
        long expiresAt = Math.min(Math.min(actor.expiresAt, subject.expiresAt),
                Math.min(Math.addExact(now, grant.maxTTLSeconds), nativeExpiration));
        if (expiresAt <= now) throw new Rejected("expired_input");
        int depth = Math.max(actor.depth, subject.depth) + 1;
        if (depth > grant.maxDepth) throw new Rejected("depth_exceeded");
        Authority allowed = actor.authority.intersect(subject.authority).intersect(grant.authority)
                .intersect(currentActor).intersect(currentSubject);
        if (!allowed.contains(requested)) throw new Rejected("authority_exceeded");
        return new Decision(requested, expiresAt, depth);
    }
}
