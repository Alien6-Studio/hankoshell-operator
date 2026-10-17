/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.Map;
import org.keycloak.common.Version;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Public non-secret discovery; no grant configuration, identities or tokens are exposed. */
@jakarta.ws.rs.ext.Provider
public final class CapabilityResource implements RealmResourceProvider, RealmResourceProviderFactory {
    private final KeycloakSession session;
    public CapabilityResource() { this.session = null; }
    private CapabilityResource(KeycloakSession session) { this.session = session; }
    @GET @jakarta.ws.rs.Path("") @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> capabilities() {
        return Map.of("contract", "bounded-delegation/software-v1", "extensionVersion", "0.1.0-SNAPSHOT",
                "keycloakVersion", Version.VERSION, "experimental", true, "maxDepth", 4, "maxTTLSeconds", 600,
                "enabled", session != null && "software-v1".equals(session.getContext().getRealm().getAttribute(GrantDocument.REALM_ATTRIBUTE))
                        && org.keycloak.common.Profile.isFeatureEnabled(org.keycloak.common.Profile.Feature.TOKEN_EXCHANGE_STANDARD_V2));
    }
    @Override public Object getResource() { return this; }
    @Override public RealmResourceProvider create(KeycloakSession session) { return new CapabilityResource(session); }
    @Override public String getId() { return "bounded-delegation"; }
    @Override public void init(org.keycloak.Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}
