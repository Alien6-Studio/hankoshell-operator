/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BoundsTest {
    private final Authority read = authority("read");
    private final Authority write = authority("read", "write");
    private final Authority none = authority();

    private static Authority authority(String... scopes) {
        Set<String> values = Set.of(scopes);
        return new Authority(values, values, Map.of("api", values), Map.of("resource", values));
    }

    private Bounds.Decision decide(Authority actor, Authority subject, Authority grant, Authority requested,
                                   Authority currentActor, Authority currentSubject) {
        return Bounds.evaluate(new Bounds.Input(actor, 1100, 0), new Bounds.Input(subject, 1050, 0),
                new Bounds.Grant(grant, 1, 120), requested, currentActor, currentSubject, 1000, 1600);
    }

    @Test void refusesWiderSubjectOrActorOrGrantOrCurrentAuthority() {
        for (int index = 0; index < 5; index++) {
            Authority[] values = {write, write, write, write, write};
            values[index] = read;
            var failure = assertThrows(Bounds.Rejected.class,
                    () -> decide(values[0], values[1], values[2], write, values[3], values[4]));
            assertEquals("authority_exceeded", failure.code());
        }
        assertEquals(read, decide(write, read, write, read, write, write).authority());
    }

    @Test void checksEachAuthorityDimensionIndependently() {
        for (Authority excess : new Authority[]{
                new Authority(Set.of("write"), Set.of(), Map.of(), Map.of()),
                new Authority(Set.of(), Set.of("write"), Map.of(), Map.of()),
                new Authority(Set.of(), Set.of(), Map.of("api", Set.of("write")), Map.of()),
                new Authority(Set.of(), Set.of(), Map.of(), Map.of("resource", Set.of("write"))),
                new Authority(Set.of(), Set.of(), Map.of(), Map.of("foreign", Set.of("read")))}) {
            assertThrows(Bounds.Rejected.class, () -> decide(read, read, read, excess, read, read));
        }
    }

    @Test void choosesEarliestExpiryWithoutRaisingNativeLifetimes() {
        long[] bounds = {1030, 1040, 1020, 1010};
        for (int earliest = 0; earliest < 4; earliest++) {
            long[] values = {1500, 1500, 1500, 1500};
            values[earliest] = bounds[earliest];
            var decision = Bounds.evaluate(new Bounds.Input(read, values[0], 0), new Bounds.Input(read, values[1], 0),
                    new Bounds.Grant(read, 1, (int) (values[2] - 1000)), read, read, read, 1000, values[3]);
            assertEquals(bounds[earliest], decision.expiresAt());
        }
    }

    @Test void refusesExpiredActorSubjectOrNativeSession() {
        for (int index = 0; index < 3; index++) {
            long[] values = {1100, 1100, 1100};
            values[index] = 1000;
            assertEquals("expired_input", assertThrows(Bounds.Rejected.class,
                    () -> Bounds.evaluate(new Bounds.Input(read, values[0], 0), new Bounds.Input(read, values[1], 0),
                            new Bounds.Grant(read, 1, 120), read, read, read, 1000, values[2])).code());
        }
    }

    @Test void checksBothBranchesOfTheChain() {
        for (int actorDepth = 0; actorDepth <= 4; actorDepth++) {
            for (int subjectDepth = 0; subjectDepth <= 4; subjectDepth++) {
                var actor = new Bounds.Input(read, 1100, actorDepth);
                var subject = new Bounds.Input(read, 1100, subjectDepth);
                if (Math.max(actorDepth, subjectDepth) >= 2) {
                    assertEquals("depth_exceeded", assertThrows(Bounds.Rejected.class,
                            () -> Bounds.evaluate(actor, subject, new Bounds.Grant(read, 2, 120), read, read, read, 1000, 1100)).code());
                } else {
                    assertEquals(Math.max(actorDepth, subjectDepth) + 1,
                            Bounds.evaluate(actor, subject, new Bounds.Grant(read, 2, 120), read, read, read, 1000, 1100).depth());
                }
            }
        }
    }

    @Test void randomizedDecisionsNeverWidenAuthority() {
        Random random = new Random(8693);
        for (int attempt = 0; attempt < 2000; attempt++) {
            Authority actor = randomAuthority(random), subject = randomAuthority(random), grant = randomAuthority(random);
            Authority currentActor = randomAuthority(random), currentSubject = randomAuthority(random);
            Authority allowed = actor.intersect(subject).intersect(grant).intersect(currentActor).intersect(currentSubject);
            var output = decide(actor, subject, grant, allowed, currentActor, currentSubject);
            assertTrue(actor.contains(output.authority()));
            assertTrue(subject.contains(output.authority()));
            assertTrue(grant.contains(output.authority()));
            assertTrue(currentActor.contains(output.authority()));
            assertTrue(currentSubject.contains(output.authority()));
        }
    }

    private Authority randomAuthority(Random random) {
        Set<String> scopes = new HashSet<>();
        for (String scope : Set.of("read", "write", "admin")) if (random.nextBoolean()) scopes.add(scope);
        return authority(scopes.toArray(String[]::new));
    }

    @Test void immutableAuthorityDoesNotFollowCallerMutations() {
        Set<String> mutable = new HashSet<>(Set.of("read"));
        Authority authority = new Authority(mutable, mutable, Map.of("api", mutable), Map.of("resource", mutable));
        mutable.add("write");
        assertEquals(read, authority);
        assertThrows(UnsupportedOperationException.class, () -> authority.permissions().get("resource").add("write"));
    }

    @Test void refusesMalformedAndOversizedAuthority() {
        assertThrows(IllegalArgumentException.class, () -> authority(""));
        assertThrows(IllegalArgumentException.class, () -> authority("read\nwrite"));
        assertThrows(IllegalArgumentException.class, () -> authority("x".repeat(513)));
        Set<String> tooMany = new HashSet<>();
        for (int i = 0; i <= 1024; i++) tooMany.add("s" + i);
        assertThrows(IllegalArgumentException.class, () -> new Authority(tooMany, Set.of(), Map.of(), Map.of()));
    }

    @Test void refusesInvalidBounds() {
        for (int depth : new int[]{0, Bounds.MAX_CHAIN_LENGTH + 1}) assertThrows(IllegalArgumentException.class, () -> new Bounds.Grant(read, depth, 120));
        for (int ttl : new int[]{0, -1}) assertThrows(IllegalArgumentException.class, () -> new Bounds.Grant(read, 1, ttl));
        assertThrows(IllegalArgumentException.class, () -> new Bounds.Input(read, 0, 0));
        assertThrows(IllegalArgumentException.class, () -> new Bounds.Input(read, 1100, -1));
    }
}
