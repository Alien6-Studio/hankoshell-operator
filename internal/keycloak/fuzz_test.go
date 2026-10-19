package keycloak

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
)

func FuzzProviderStatusDecision(f *testing.F) {
	f.Add("404: not found", uint16(403))
	f.Add("403: forbidden", uint16(404))
	f.Add("native body", uint16(500))
	f.Fuzz(func(t *testing.T, text string, status uint16) {
		untrusted := errors.New(text)
		if IsNotFound(untrusted) || IsForbidden(untrusted) {
			t.Fatal("native text became an HTTP status")
		}
		wrapped := fmt.Errorf("%s: %w", text, &StatusError{Code: int(status)})
		if IsNotFound(wrapped) != (status == http.StatusNotFound) || IsForbidden(wrapped) != (status == http.StatusForbidden) {
			t.Fatal("typed status decision depends on untrusted text")
		}
	})
}

func FuzzBoundedDelegationDocument(f *testing.F) {
	seed := boundedTestDocument()
	encoded, _ := boundedDelegationJSON(seed)
	for _, value := range []string{string(encoded), `{}`, string(encoded) + `{}`, strings.Replace(string(encoded), `"ownerUID":`, `"ownerUID":"foreign","ownerUID":`, 1), strings.Repeat(" ", 128*1024+1)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		current := map[string]any{"id": seed.Audience.ID, "attributes": map[string]any{BoundedDelegationAttribute: value}}
		document, err := ownedBoundedDocument(current, seed.OwnerUID)
		if err != nil || document == nil {
			return
		}
		if len(value) > 128*1024 || document.OwnerUID != seed.OwnerUID || document.Audience.ID != seed.Audience.ID {
			t.Fatal("unbound or oversized delegation recovery document accepted")
		}
		if _, err := boundedDelegationJSON(*document); err != nil {
			t.Fatal("accepted an invalid delegation phase or authority envelope")
		}
		if _, err := ownedBoundedDocument(current, "foreign-owner"); err == nil {
			t.Fatal("delegation recovery accepted a foreign owner")
		}
		current["id"] = "foreign-client"
		if _, err := ownedBoundedDocument(current, seed.OwnerUID); err == nil {
			t.Fatal("delegation recovery accepted a foreign physical client")
		}
	})
}

func FuzzBoundedDelegationActorMarker(f *testing.F) {
	actor := BoundedDelegationBinding{ID: "actor-id", Attribute: adoption.ClientOwnerUIDKey, Value: "actor-uid"}
	seed := boundedDelegationActorMarker{Version: 1, Actor: actor, Owners: map[string]string{"audience-id": "owner-uid"}}
	encoded, _ := json.Marshal(seed)
	for _, value := range []string{string(encoded), `{}`, `{"owners":{"audience-id":"owner-uid"}}`, strings.Replace(string(encoded), `"version":1`, `"version":2`, 1), strings.Replace(string(encoded), `"actor":`, `"actor":{},"actor":`, 1), strings.Repeat(" ", 32*1024+1)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		current := map[string]any{"attributes": map[string]any{BoundedDelegationActorAttribute: value}}
		marker, err := parseBoundedActorMarker(current, actor, "audience-id", "owner-uid")
		if err != nil {
			return
		}
		if len(value) > 32*1024 || !validBoundedActorMarker(marker) || marker.Actor != actor || !boundedActorEnvelope(value, actor) {
			t.Fatal("unbound or oversized shared actor recovery marker accepted")
		}
		if owner, present := marker.Owners["audience-id"]; present && owner != "owner-uid" {
			t.Fatal("shared actor marker replaced sibling ownership")
		}
		foreign := actor
		foreign.Value = "foreign-uid"
		if _, err := parseBoundedActorMarker(current, foreign, "audience-id", "owner-uid"); err == nil {
			t.Fatal("shared actor marker accepted a replacement workload UID")
		}
	})
}

func FuzzAuthorizationJournal(f *testing.F) {
	journal := authorizationJournal{Version: 1, OwnerUID: "owner-uid", Objects: AuthorizationManagedObjects{ResourceServerID: "client-id", Scopes: []AuthorizationManagedReference{{Name: "read", ID: "scope-id"}}}}
	seed, _ := json.Marshal(journal)
	for _, value := range []string{string(seed), `{}`, strings.Replace(string(seed), `"ownerUID":`, `"ownerUID":"foreign","ownerUID":`, 1), strings.Repeat(" ", maxAuthorizationJournalBytes+1)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		doc := map[string]any{"attributes": map[string]any{authorizationOwnerAttribute: value}}
		objects, present, err := parseAuthorizationJournal(doc, "owner-uid", "client-id")
		if err != nil || !present {
			return
		}
		if len(value) > maxAuthorizationJournalBytes || objects.ResourceServerID != "client-id" || !validAuthorizationObjects(objects) {
			t.Fatal("unbound ownership journal accepted")
		}
		if _, _, err := parseAuthorizationJournal(doc, "foreign-owner", "client-id"); err == nil {
			t.Fatal("foreign owner accepted")
		}
		if _, _, err := parseAuthorizationJournal(doc, "owner-uid", "foreign-client"); err == nil {
			t.Fatal("foreign client accepted")
		}
	})
}

func TestAuthorizationJournalRejectsAmbiguousIdentity(t *testing.T) {
	for _, value := range []string{
		`{"version":1,"ownerUID":"foreign","ownerUID":"owner-uid","objects":{"resourceServerID":"client-id"}}`,
		`{"version":1,"ownerUID":"owner-uid","objects":{"resourceServerID":"foreign","resourceServerID":"client-id"}}`,
	} {
		doc := map[string]any{"attributes": map[string]any{authorizationOwnerAttribute: value}}
		if _, _, err := parseAuthorizationJournal(doc, "owner-uid", "client-id"); err == nil {
			t.Fatal("ambiguous ownership identity accepted")
		}
	}
}
