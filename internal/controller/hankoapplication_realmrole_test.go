package controller

import (
	"context"
	"strings"
	"testing"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func strPtr(s string) *string { return &s }

func TestTokenClaimSourceCount(t *testing.T) {
	tests := []struct {
		name  string
		claim hankoshv1alpha1.ApplicationTokenClaim
		want  int
	}{
		{name: "none", claim: hankoshv1alpha1.ApplicationTokenClaim{}, want: 0},
		{name: "userAttribute only", claim: hankoshv1alpha1.ApplicationTokenClaim{UserAttribute: "tenant"}, want: 1},
		{name: "value only", claim: hankoshv1alpha1.ApplicationTokenClaim{Value: strPtr("x")}, want: 1},
		{name: "realmRoles only", claim: hankoshv1alpha1.ApplicationTokenClaim{RealmRoles: true}, want: 1},
		{name: "userAttribute and value", claim: hankoshv1alpha1.ApplicationTokenClaim{UserAttribute: "tenant", Value: strPtr("x")}, want: 2},
		{name: "all three", claim: hankoshv1alpha1.ApplicationTokenClaim{UserAttribute: "tenant", Value: strPtr("x"), RealmRoles: true}, want: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tokenClaimSourceCount(tt.claim); got != tt.want {
				t.Errorf("tokenClaimSourceCount = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestProtocolMapperForClientRealmRoles(t *testing.T) {
	claim := hankoshv1alpha1.ApplicationTokenClaim{
		Name:            "trunx-roles",
		Claim:           "trunx_roles",
		RealmRoles:      true,
		RealmRolePrefix: "trunx-",
	}
	mapper, err := protocolMapperForClient("trunx", "trunx-dashboard", claim)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mapper.ProtocolMapper != "oidc-usermodel-realm-role-mapper" {
		t.Errorf("provider = %q, want oidc-usermodel-realm-role-mapper", mapper.ProtocolMapper)
	}
	if mapper.Protocol != "openid-connect" {
		t.Errorf("protocol = %q, want openid-connect", mapper.Protocol)
	}
	if mapper.Config["claim.name"] != "trunx_roles" {
		t.Errorf("claim.name = %q, want trunx_roles", mapper.Config["claim.name"])
	}
	if mapper.Config["multivalued"] != "true" {
		t.Errorf("multivalued = %q, want true", mapper.Config["multivalued"])
	}
	if mapper.Config["usermodel.realmRoleMapping.rolePrefix"] != "trunx-" {
		t.Errorf("rolePrefix = %q, want trunx-", mapper.Config["usermodel.realmRoleMapping.rolePrefix"])
	}
	// The claim must reach the userinfo endpoint: Trunx reads roles from userinfo.
	if mapper.Config["userinfo.token.claim"] != "true" {
		t.Errorf("userinfo.token.claim = %q, want true", mapper.Config["userinfo.token.claim"])
	}
}

func TestProtocolMapperForClientRejectsMultipleSources(t *testing.T) {
	claim := hankoshv1alpha1.ApplicationTokenClaim{
		Name:       "bad",
		Claim:      "trunx_roles",
		RealmRoles: true,
		Value:      strPtr("x"),
	}
	if _, err := protocolMapperForClient("trunx", "trunx-dashboard", claim); err == nil {
		t.Fatal("expected error for multiple value sources, got nil")
	}
}

func TestAuthorityTokenClaimsAreRejectedAtPreflightAndRuntime(t *testing.T) {
	reservedClaims := []string{
		"sub",
		"hanko_token_use",
		"nonce",
		"auth_time",
		"acr",
		"amr",
		"at_hash",
		"c_hash",
		"s_hash",
		"client_id",
	}
	for _, root := range structuredReservedTokenClaims {
		reservedClaims = append(reservedClaims, root, root+".nested.value")
	}
	fixed := "spoofed"
	owner := tokenClaimOwner{namespace: "default", name: "console", generation: 9, realm: "alien6", clientID: "console"}

	for _, claimName := range reservedClaims {
		t.Run(claimName, func(t *testing.T) {
			claim := hankoshv1alpha1.ApplicationTokenClaim{Name: "unsafe", Claim: claimName, Value: &fixed}

			statuses, err := preflightTokenClaims(owner.namespace, owner.name, owner.generation, []hankoshv1alpha1.ApplicationTokenClaim{claim}, nil)
			if err == nil || !strings.Contains(err.Error(), "reserved claim") {
				t.Fatalf("preflight error = %v, want reserved claim rejection", err)
			}
			if len(statuses) != 1 || conditionReason(statuses[0].Conditions, "Synced") != "Invalid" {
				t.Fatalf("preflight status = %#v, want Invalid", statuses)
			}

			status, err := reconcileClientTokenClaim(context.Background(), nil, owner, claim, nil, map[string]struct{}{})
			if err == nil || !strings.Contains(err.Error(), "reserved claim") {
				t.Fatalf("runtime error = %v, want reserved claim rejection", err)
			}
			if conditionReason(status.Conditions, "Synced") != "Invalid" {
				t.Fatalf("runtime status = %#v, want Invalid", status)
			}
		})
	}
}

func TestAuthorityTokenClaimPrefixMatchingStopsAtDotBoundary(t *testing.T) {
	fixed := "safe"
	allowedClaims := []string{
		"hanko_token_use.detail",
		"nonce.detail",
		"auth_time.detail",
		"acr.detail",
		"amr.detail",
		"at_hash.detail",
		"c_hash.detail",
		"s_hash.detail",
		"client_id.detail",
	}
	for _, root := range structuredReservedTokenClaims {
		allowedClaims = append(allowedClaims, root+"suffix")
	}
	for _, claimName := range allowedClaims {
		t.Run(claimName, func(t *testing.T) {
			claim := hankoshv1alpha1.ApplicationTokenClaim{Name: "safe", Claim: claimName, Value: &fixed}
			if _, err := protocolMapperForClient("default", "console", claim); err != nil {
				t.Fatalf("near-match claim %q rejected: %v", claimName, err)
			}
		})
	}
}
