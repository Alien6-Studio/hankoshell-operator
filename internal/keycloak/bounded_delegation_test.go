package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBoundedDelegationCapabilityIsStrictReadOnlyDiscovery(t *testing.T) {
	valid := BoundedDelegationCapability{Contract: "bounded-delegation/software-v1", ExtensionVersion: "0.1.0-rc.1",
		KeycloakVersion: "26.7.5", Experimental: true, Enabled: true, MaxDepth: 4, MaxTTLSeconds: 600}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		status     int
		accept     bool
	}{
		{"qualified deployment profile", string(encoded), 200, true},
		{"ambiguous snapshot", strings.Replace(string(encoded), "0.1.0-rc.1", "0.1.0-SNAPSHOT", 1), 200, false},
		{"unreviewed candidate", strings.Replace(string(encoded), "0.1.0-rc.1", "0.1.0-rc.2", 1), 200, false},
		{"other supported version", strings.Replace(string(encoded), "26.7.5", "26.8.1", 1), 200, true},
		{"legacy deployment remains readable", strings.Replace(string(encoded), "26.7.5", "26.8.0", 1), 200, true},
		{"compatible patch with full contract", strings.Replace(string(encoded), "26.7.5", "26.8.2", 1), 200, true},
		{"compatible minor with full contract", strings.Replace(string(encoded), "26.7.5", "26.10.0", 1), 200, true},
		{"below feature floor", strings.Replace(string(encoded), "26.7.5", "26.7.4", 1), 200, false},
		{"prerelease", strings.Replace(string(encoded), "26.7.5", "26.8.2-rc.1", 1), 200, false},
		{"changed contract on newer patch", strings.Replace(strings.Replace(string(encoded), "26.7.5", "26.8.2", 1), "software-v1", "software-v2", 1), 200, false},
		{"changed bounds on newer patch", strings.Replace(strings.Replace(string(encoded), "26.7.5", "26.8.2", 1), `"maxDepth":4`, `"maxDepth":5`, 1), 200, false},
		{"changed extension on newer patch", strings.Replace(strings.Replace(string(encoded), "26.7.5", "26.8.2", 1), "0.1.0-rc.1", "0.2.0", 1), 200, false},
		{"stock provider", "", 404, false},
		{"disabled server feature", strings.Replace(string(encoded), `"enabled":true`, `"enabled":false`, 1), 200, false},
		{"unknown version", strings.Replace(string(encoded), "26.7.5", "99.0.0", 1), 200, false},
		{"duplicate key", strings.Replace(string(encoded), `"maxDepth":4`, `"maxDepth":4,"maxDepth":5`, 1), 200, false},
		{"unexpected field", strings.TrimSuffix(string(encoded), "}") + `,"token":"withheld"}`, 200, false},
		{"trailing document", string(encoded) + "{}", 200, false},
		{"oversized body", strings.Repeat("x", 8193), 200, false},
		{"upstream outage", "withheld", 503, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodGet || r.URL.Path != "/realms/acme/bounded-delegation" || r.Header.Get("Authorization") != "" {
					t.Error("discovery mutated state or sent administrative credentials")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			capability, err := New(server.URL, "operator", "secret", WithInsecureHTTP()).BoundedDelegationCapability(context.Background(), "acme")
			if tc.accept != (err == nil) || requests != 1 {
				t.Fatalf("discovery accepted=%v, requests=%d", err == nil, requests)
			}
			if !tc.accept && tc.status != 503 && !errors.Is(err, ErrBoundedDelegationUnsupported) {
				t.Fatal("unsupported capability was not classified")
			}
			if tc.accept && capability.Contract != valid.Contract {
				t.Fatal("discovery lost its profile identity")
			}
		})
	}
}

func boundedTestDocument() BoundedDelegationDocument {
	actor := BoundedDelegationBinding{ID: "actor-uuid", Attribute: adoption.ApplicationOwnerKey, Value: "actor-uid"}
	subject := BoundedDelegationBinding{ID: "subject-uuid", Attribute: adoption.ApplicationOwnerKey, Value: "subject-uid"}
	return BoundedDelegationDocument{Version: 1, Phase: "Committed", OwnerUID: "resource-server-uid", Revision: "sha256:" + strings.Repeat("a", 64), RealmID: "realm-uuid",
		Audience: BoundedDelegationBinding{ID: "client-uuid", Attribute: adoption.ApplicationOwnerKey, Value: "api-uid"},
		Grants: []BoundedDelegationGrant{{Name: "delegate-read", Actor: actor, Subject: subject, MaxDepth: 2, MaxTTLSeconds: 30,
			Authority: BoundedDelegationAuthority{Scopes: []string{}, RealmRoles: []string{}, ClientRoles: map[string][]string{}, Permissions: map[string][]string{"resource": {"read"}}},
			Conditions: []BoundedDelegationCondition{{Kind: "client", ID: actor.ID, Attribute: actor.Attribute, Value: actor.Value},
				{Kind: "client", ID: subject.ID, Attribute: subject.Attribute, Value: subject.Value}}}}}
}

func TestBoundedDelegationOwnershipRequiresSelfUIDAndKnownEnvelope(t *testing.T) {
	document := boundedTestDocument()
	encoded, err := boundedDelegationJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	app := &Application{ID: document.Audience.ID, Attributes: map[string]string{adoption.ApplicationOwnerKey: "api-uid", BoundedDelegationAttribute: string(encoded)}}
	if !ApplicationOwned(app, "api-uid") || ApplicationOwned(app, "replacement-uid") {
		t.Fatal("known sibling grant changed the application's UID boundary")
	}
	for _, invalid := range []string{`{}`, strings.Replace(string(encoded), `"version":1`, `"version":2`, 1),
		strings.Replace(string(encoded), `"api-uid"`, `"foreign-uid"`, 1), string(encoded) + `{}`} {
		app.Attributes[BoundedDelegationAttribute] = invalid
		if ApplicationOwned(app, "api-uid") {
			t.Fatal("malformed or foreign grant was treated as owned metadata")
		}
	}
	for _, kind := range []string{"application", "service_account"} {
		attribute := adoption.ApplicationOwnerKey
		if kind == "service_account" {
			attribute = adoption.ClientOwnerUIDKey
		}
		actor := BoundedDelegationBinding{ID: "actor-uuid", Attribute: attribute, Value: "actor-uid"}
		marker := boundedDelegationActorMarker{Version: 1, Actor: actor, Owners: map[string]string{"client-uuid": "resource-server-uid"}}
		value, _ := json.Marshal(marker)
		current := &Application{ID: actor.ID, Attributes: map[string]string{attribute: actor.Value, BoundedDelegationActorAttribute: string(value)}}
		if kind == "service_account" {
			current.Attributes[adoption.ClientOwnerKindKey] = "HankoServiceAccount"
			if !ServiceAccountOwned(current, actor.Value) {
				t.Fatal("valid service-account actor envelope was refused")
			}
		} else if !ApplicationOwned(current, actor.Value) {
			t.Fatal("valid application actor envelope was refused")
		}
		marker.Actor.Value = "replacement-uid"
		value, _ = json.Marshal(marker)
		current.Attributes[BoundedDelegationActorAttribute] = string(value)
		if boundedClientEnvelope(current, "actor-uid", attribute) {
			t.Fatal("actor marker granted ownership to a replacement UID")
		}
	}
}

func TestBoundedDelegationRejectsOperationalKeysInDesiredApplications(t *testing.T) {
	for _, key := range []string{BoundedDelegationAttribute, BoundedDelegationActorAttribute, "oauth.bounded-delegation.future"} {
		if !adoption.ReservedAttribute(key) {
			t.Fatal("delegation metadata is writable through desired client attributes")
		}
		attributes := map[string]any{}
		mergeAppAttributes(attributes, map[string]string{key: "forged", "normal": "value"})
		if _, present := attributes[key]; present || attributes["normal"] != "value" {
			t.Fatal("legacy attribute merge accepted operational delegation metadata")
		}
	}
}

func TestBoundedDelegationUserReadWitnessCannotEnumerateOrChangeIdentity(t *testing.T) {
	paths := []string{"/admin/realms/acme/clients/actor-uuid/service-account-user", "/admin/realms/acme/users/user-uuid/role-mappings/realm/composite",
		"/admin/realms/acme/users/user-uuid/groups?first=0&max=129&briefRepresentation=true"}
	for _, path := range paths {
		request, err := http.NewRequest(http.MethodGet, "https://keycloak.test"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if validateBoundedDelegationRead(request, request.URL.EscapedPath()) == nil {
			t.Fatal("unbound service-account read was allowed")
		}
		request = request.WithContext(context.WithValue(request.Context(), boundedDelegationReadKey{}, boundedDelegationRead{realm: "acme", clientID: "actor-uuid", userID: "user-uuid"}))
		if err := validateBoundedDelegationRead(request, request.URL.EscapedPath()); err != nil {
			t.Fatal("verified service-account read was refused", err)
		}
		foreign := request.Clone(request.Context())
		foreign.URL.Path = strings.Replace(request.URL.Path, "acme", "foreign", 1)
		if validateBoundedDelegationRead(foreign, foreign.URL.EscapedPath()) == nil {
			t.Fatal("witness crossed a realm boundary")
		}
	}
}

func TestBoundedDelegationIntersectionUsesEveryResourceAndScope(t *testing.T) {
	actor := boundedDelegationMember{binding: BoundedDelegationBinding{ID: "actor"}, roles: []string{"read"}, groups: []string{"team"}}
	model := AuthorizationModel{Permissions: []AuthorizationPermission{{Name: "allow", Resources: []string{"document"}, Scopes: []string{"read"}}}}
	conditions := map[string][]BoundedDelegationCondition{"allow": {{Kind: "role", ID: "read"}}}
	if !boundedMemberGranted(model, conditions, actor, "document", "read") {
		t.Fatal("declared effective role was denied")
	}
	for _, pair := range [][2]string{{"document", "write"}, {"foreign", "read"}} {
		if boundedMemberGranted(model, conditions, actor, pair[0], pair[1]) {
			t.Fatal("intersection widened a resource or scope")
		}
	}
	for _, condition := range []BoundedDelegationCondition{{Kind: "client", ID: "foreign"}, {Kind: "role", ID: "admin"}, {Kind: "group", ID: "other"}} {
		if boundedMemberMatches(actor, []BoundedDelegationCondition{condition}) {
			t.Fatal("foreign principal matched the software identity")
		}
	}
}

func TestBoundedDelegationJournalRejectsMalformedOrWidenedEnvelopes(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*BoundedDelegationDocument)
	}{
		{"unknown phase", func(d *BoundedDelegationDocument) { d.Phase = "Unknown" }},
		{"forged revision", func(d *BoundedDelegationDocument) { d.Revision = "approved" }},
		{"same identity", func(d *BoundedDelegationDocument) { d.Grants[0].Subject = d.Grants[0].Actor }},
		{"ambient scopes", func(d *BoundedDelegationDocument) { d.Grants[0].Authority.Scopes = []string{"admin"} }},
		{"null authority dimension", func(d *BoundedDelegationDocument) { d.Grants[0].Authority.Scopes = nil }},
		{"ambient roles", func(d *BoundedDelegationDocument) { d.Grants[0].Authority.RealmRoles = []string{"admin"} }},
		{"empty permission", func(d *BoundedDelegationDocument) {
			d.Grants[0].Authority.Permissions = map[string][]string{"resource": {}}
		}},
		{"unknown principal", func(d *BoundedDelegationDocument) { d.Grants[0].Conditions[0].Kind = "user" }},
		{"foreign group marker", func(d *BoundedDelegationDocument) {
			d.Grants[0].Conditions = []BoundedDelegationCondition{{Kind: "group", ID: "group", Attribute: "arbitrary", Value: "uid"}}
		}},
		{"ambiguous identity pair", func(d *BoundedDelegationDocument) {
			other := d.Grants[0]
			other.Name = "second"
			d.Grants = append(d.Grants, other)
		}},
		{"depth excess", func(d *BoundedDelegationDocument) { d.Grants[0].MaxDepth = 5 }},
		{"lifetime excess", func(d *BoundedDelegationDocument) { d.Grants[0].MaxTTLSeconds = 601 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := boundedTestDocument()
			tc.edit(&document)
			if _, err := boundedDelegationJSON(document); !errors.Is(err, ErrBoundedDelegationUnsupported) {
				t.Fatal("unsafe native envelope accepted")
			}
		})
	}
}
