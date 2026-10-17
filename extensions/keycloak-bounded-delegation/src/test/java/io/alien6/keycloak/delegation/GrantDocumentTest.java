/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GrantDocumentTest {
    private static final String VALID = """
            {"version":1,"phase":"Committed","ownerUID":"owner","revision":"revision","realmID":"realm",
             "audience":{"id":"api","attribute":"owner","value":"api-uid"},"grants":[{
             "name":"read","actor":{"id":"actor","attribute":"owner","value":"actor-uid"},
             "subject":{"id":"subject","attribute":"owner","value":"subject-uid"},
             "conditions":[{"kind":"role","id":"shared-role"}],
             "authority":{"scopes":[],"realmRoles":[],"clientRoles":{},"permissions":{"resource":["read"]}},
             "maxDepth":2,"maxTTLSeconds":30}]}
            """;

    @Test void acceptsBoundedTypedConfiguration() {
        var document = GrantDocument.parse(VALID);
        assertEquals(1, document.version());
        assertEquals("Committed", document.phase());
        assertEquals(30, document.grants().getFirst().maxTTLSeconds());
        assertThrows(UnsupportedOperationException.class, () -> document.grants().clear());
    }

    @Test void refusesAmbiguousJsonAndCoercions() {
        for (String invalid : List.of(
                VALID.replace("\"version\":1", "\"version\":1,\"version\":2"),
                VALID + "{}", VALID.replace("\"version\":1", "\"version\":\"1\""),
                VALID.replace("\"version\":1", "\"version\":1.5"),
                VALID.replace("\"version\":1", "\"version\":null"),
                VALID.replace("\"phase\":\"Committed\"", "\"phase\":null"),
                VALID.replace("\"phase\":\"Committed\"", "\"phase\":\"Committed\",\"unexpected\":true"),
                VALID.replace("\"maxTTLSeconds\":30", "\"maxTTLSeconds\":9999999999999999999999999"))) {
            assertEquals("grant_invalid", assertThrows(Bounds.Rejected.class, () -> GrantDocument.parse(invalid)).code());
        }
    }

    @Test void refusesMissingIdentityAndUnboundedGrant() {
        for (String invalid : List.of(VALID.replace("\"id\":\"actor\"", "\"id\":\"subject\""),
                VALID.replace("\"actor-uid\"", "\"\""), VALID.replace("\"maxDepth\":2", "\"maxDepth\":5"),
                VALID.replace("\"maxTTLSeconds\":30", "\"maxTTLSeconds\":601"),
                VALID.replace("\"permissions\":{\"resource\":[\"read\"]}", "\"permissions\":{}"))) {
            assertThrows(Bounds.Rejected.class, () -> GrantDocument.parse(invalid));
        }
    }

    @Test void refusesOversizedAndDeeplyNestedConfiguration() {
        assertThrows(Bounds.Rejected.class, () -> GrantDocument.parse("x".repeat(128 * 1024 + 1)));
        assertThrows(Bounds.Rejected.class, () -> GrantDocument.parse("[".repeat(10000) + "0" + "]".repeat(10000)));
        assertThrows(Bounds.Rejected.class, () -> GrantDocument.parse(null));
    }
}
