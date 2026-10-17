package keycloak

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
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
