package authorization

import (
	"errors"
	"testing"
)

func TestValidateCapabilitiesFailsClosed(t *testing.T) {
	model := Model{
		Resources: []Resource{{Name: "invoice", URIs: []string{"/invoices/*"}}},
		Permissions: []Permission{{
			Name: "read", Principals: []Principal{{Kind: "service_account", Ref: "worker"}},
		}},
	}
	for _, test := range []struct {
		name string
		caps Capabilities
	}{
		{name: "resource objects", caps: Capabilities{ResourceURIMatching: true, ServiceAccountPrincipals: true}},
		{name: "URI matching", caps: Capabilities{ResourceObjects: true, ServiceAccountPrincipals: true}},
		{name: "service accounts", caps: Capabilities{ResourceObjects: true, ResourceURIMatching: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCapabilities(model, test.caps)
			if !errors.Is(err, ErrCapabilityUnsupported) {
				t.Fatalf("ValidateCapabilities() error = %v, want ErrCapabilityUnsupported", err)
			}
		})
	}
}

func TestValidateCapabilitiesAcceptsSupportedModel(t *testing.T) {
	model := Model{
		Scopes:    []Scope{{Name: "read"}},
		Resources: []Resource{{Name: "invoice", URIs: []string{"/invoices/*"}}},
		Permissions: []Permission{{Name: "read", Principals: []Principal{
			{Kind: "realm_role", Ref: "reader"},
			{Kind: "application", Ref: "web"},
			{Kind: "service_account", Ref: "worker"},
		}}},
	}
	caps := Capabilities{ScopeGrants: true, ResourceObjects: true, ResourceURIMatching: true, RolePrincipals: true, ApplicationPrincipals: true, ServiceAccountPrincipals: true}
	if err := ValidateCapabilities(model, caps); err != nil {
		t.Fatalf("ValidateCapabilities() = %v", err)
	}
}
