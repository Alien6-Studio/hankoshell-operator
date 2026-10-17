/* SPDX-License-Identifier: Apache-2.0 */
package io.alien6.keycloak.delegation;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

public final class BoundedTokenExchangeProviderFactory implements TokenExchangeProviderFactory, EnvironmentDependentProviderFactory {
    @Override public TokenExchangeProvider create(KeycloakSession session) { return new BoundedTokenExchangeProvider(); }
    @Override public String getId() { return "bounded-delegation"; }
    @Override public int order() { return 100; }
    @Override public boolean isSupported(Config.Scope config) { return Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE_STANDARD_V2); }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}
