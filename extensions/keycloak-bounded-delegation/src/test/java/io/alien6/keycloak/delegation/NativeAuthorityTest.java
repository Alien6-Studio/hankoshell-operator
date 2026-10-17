/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessToken;
import static org.junit.jupiter.api.Assertions.*;

class NativeAuthorityTest {
    @Test void stripsMapperAuthorityAndUnselectedPermissionClaims() {
        AccessToken token = new AccessToken();
        token.setOtherClaims("groups", Set.of("administrators"));
        token.setOtherClaims("may_act", Map.of("sub", "foreign"));
        token.setOtherClaims("arbitrary_permission", "admin");
        token.setRealmAccess(new AccessToken.Access().roles(Set.of("admin")));
        token.addAccess("foreign").addRole("owner");
        var expected = new Authority(Set.of("read"), Set.of(), Map.of(), Map.of("document", Set.of("read")));
        NativeAuthority.apply(token, expected);
        assertEquals(expected, NativeAuthority.fromToken(token));
        assertTrue(token.getOtherClaims().isEmpty());
        assertNull(token.getAuthorizationDetails());
    }

    @Test void refusesMalformedActorHistoryWithoutFollowingUnboundedChains() {
        assertEquals(1, ChainState.actorDepth(Map.of("sub", "actor")));
        assertEquals(2, ChainState.actorDepth(Map.of("sub", "actor", "act", Map.of("sub", "previous"))));
        assertThrows(Bounds.Rejected.class, () -> ChainState.actorDepth(Map.of("sub", 12)));
        Object history = Map.of("sub", "actor");
        for (int i = 0; i < 4; i++) history = Map.of("sub", "actor", "act", history);
        Object tooDeep = history;
        assertThrows(Bounds.Rejected.class, () -> ChainState.actorDepth(tooDeep));
    }
}
