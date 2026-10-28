package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTaskCapabilityCannotBeInferredOrWeakened(t *testing.T) {
	valid := taskDelegationCapability{Contract: "bounded-delegation/task-reference-v1", ExtensionVersion: "0.1.0-rc.1",
		KeycloakVersion: "26.8.1", Enabled: true, Experimental: true, StateStore: "database", OnlineRequired: true, SingleUseApproval: true,
		MaxDepth: 1, MaxTTLSeconds: 600}
	data, _ := json.Marshal(valid)
	for _, body := range []string{string(data), `{}`, strings.Replace(string(data), `"enabled":true`, `"enabled":false`, 1),
		strings.Replace(string(data), "0.1.0-rc.1", "0.1.0-SNAPSHOT", 1),
		strings.Replace(string(data), "0.1.0-rc.1", "0.1.0-rc.2", 1),
		strings.Replace(string(data), `"stateStore":"database"`, `"stateStore":"cache"`, 1),
		strings.Replace(string(data), `"onlineRequired":true`, `"onlineRequired":false`, 1),
		strings.Replace(string(data), `"singleUseApproval":true`, `"singleUseApproval":false`, 1),
		strings.Replace(string(data), `"maxDepth":1`, `"maxDepth":4`, 1),
		strings.Replace(string(data), `"26.8.1"`, `"26.8.2"`, 1),
		strings.Replace(string(data), `"enabled":true`, `"enabled":true,"enabled":false`, 1),
		strings.TrimSuffix(string(data), "}") + `,"extra":true}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/realms/managed/bounded-delegation/task-context" || r.Header.Get("Authorization") != "" {
				t.Error("task discovery crossed its read-only boundary")
			}
			_, _ = w.Write([]byte(body))
		}))
		client := New(server.URL, "operator", "withheld")
		client.httpClient = server.Client()
		_, err := client.taskDelegationCapability(context.Background(), "managed")
		server.Close()
		if (err == nil) != (body == string(data)) {
			t.Fatal("task capability accepted a missing or weakened invariant")
		}
	}
}

func TestTaskDocumentHasAnExplicitLegacyRefusalGuard(t *testing.T) {
	document := boundedTestDocument()
	document.Version, document.Profile = 2, "task-bound-software"
	if _, err := boundedDelegationJSON(document); err == nil {
		t.Fatal("multi-hop task grant accepted")
	}
	document.Grants[0].MaxDepth = 1
	if _, err := boundedDelegationJSON(document); err != nil {
		t.Fatal("valid task journal refused", err)
	}
	document.Profile = ""
	if _, err := boundedDelegationJSON(document); err == nil {
		t.Fatal("task document lost its explicit profile")
	}
	document = boundedTestDocument()
	data, err := boundedDelegationJSON(document)
	if err != nil || strings.Contains(string(data), `"profile"`) {
		t.Fatal("default software wire changed")
	}
}
