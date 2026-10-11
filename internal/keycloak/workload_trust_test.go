package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestKubernetesTrustClosedNativeProjectionAndOwnerOnlyPreservation(t *testing.T) {
	base := map[string]any{"internalId": "native-uuid", "alias": "cluster", "providerId": "kubernetes", "enabled": true, "hideOnLogin": true, "types": []string{"CLIENT_ASSERTION"}, "displayName": "Reviewed", "firstBrokerLoginFlowAlias": "first broker login", "config": map[string]any{"issuer": "https://cluster.example.test", "syncMode": "LEGACY"}}
	for _, field := range []string{"qualified", "unknown root", "unknown config", "token storage", "custom flow", "bad age", "bad skew", "duplicate"} {
		t.Run(field, func(t *testing.T) {
			b, _ := json.Marshal(base)
			var p map[string]any
			_ = json.Unmarshal(b, &p)
			switch field {
			case "unknown root":
				p["unknownSecurity"] = true
			case "unknown config":
				p["config"].(map[string]any)["secret-sentinel"] = "excluded"
			case "token storage":
				p["storeToken"] = true
			case "custom flow":
				p["firstBrokerLoginFlowAlias"] = "custom"
			case "bad age":
				p["config"].(map[string]any)["fedClientAssertionMaxExp"] = "599"
			case "bad skew":
				p["config"].(map[string]any)["allowedClockSkew"] = "unsafe"
			}
			b, _ = json.Marshal(p)
			if field == "duplicate" {
				b = []byte(strings.Replace(string(b), `"enabled":true`, `"enabled":true,"enabled":false`, 1))
			}
			var native KubernetesTrust
			err := json.Unmarshal(b, &native)
			if field == "qualified" {
				if err != nil || !native.Qualified || native.Config.MaxAge != 3600 || native.Config.ClockSkew != "10" {
					t.Fatal("qualified native defaults lost")
				}
			} else if err == nil && native.Qualified {
				t.Fatal("unqualified native data accepted")
			}
			projected, _ := json.Marshal(native)
			if strings.Contains(string(projected), "secret-sentinel") {
				t.Fatal("arbitrary config entered projection")
			}
		})
	}
	var before KubernetesTrust
	b, _ := json.Marshal(base)
	if err := json.Unmarshal(b, &before); err != nil {
		t.Fatal(err)
	}
	puts := 0
	var after map[string]any
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			writeAuthorizationJSON(w, map[string]any{"access_token": "fixture", "expires_in": 300})
			return
		}
		if r.Method == http.MethodGet {
			writeAuthorizationJSON(w, base)
			return
		}
		puts++
		_ = json.NewDecoder(r.Body).Decode(&after)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()
	c := New(s.URL, "writer", "credential", WithInsecureHTTP())
	hash := workloadtrust.Digest("public-test", 1)
	plan, err := workloadtrust.Compile(workloadtrust.Intent{RealmRef: "managed", Alias: "cluster", Issuer: before.Config.Issuer, NamespaceUID: "cluster-uid", CAHash: hash, MaxAge: 600}, workloadtrust.References{Owner: "owner-uid", Generation: 1, ProviderID: before.InternalID, RealmID: "realm-uuid", SourceHash: hash, FreshReferencesHash: hash, FlowHash: hash, DependenciesHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := plan.Journal(WorkloadTrustStateHash(before), "Acquired")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := (adoption.Receipt{ContractVersion: adoption.Version, TargetKind: "HankoWorkloadTrust", TargetUID: "owner-uid", CandidateHash: hash}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AcquireKubernetesWorkloadTrustOwnership(context.Background(), "managed", before, "owner-uid", journal, receipt); err != nil {
		t.Fatal(err)
	}
	if puts != 1 || after["displayName"] != base["displayName"] || after["internalId"] != base["internalId"] {
		t.Fatal("owner-only preservation failed")
	}
	config := after["config"].(map[string]any)
	if _, rewritten := config["fedClientAssertionMaxExp"]; rewritten {
		t.Fatal("acquisition normalized native age")
	}
	if len(config) != 5 {
		t.Fatal("acquisition wrote extra config")
	}
	base["displayName"] = "concurrent edit"
	if err := c.AcquireKubernetesWorkloadTrustOwnership(context.Background(), "managed", before, "owner-uid", journal, receipt); err == nil || puts != 1 {
		t.Fatal("acquisition followed changed preservation state")
	}
}

func TestKubernetesTrustInventoryReadsEveryPageAndRejectsPartialAbsence(t *testing.T) {
	for _, test := range []struct {
		name       string
		count      int
		null, deny bool
	}{{"second page", 101, false, false}, {"overflow", 1025, false, false}, {"null", 0, true, false}, {"denied", 101, false, true}} {
		t.Run(test.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/token") {
					writeAuthorizationJSON(w, map[string]any{"access_token": "fixture", "expires_in": 300})
					return
				}
				first, _ := strconv.Atoi(r.URL.Query().Get("first"))
				if test.deny && first == 100 {
					w.WriteHeader(403)
					return
				}
				if test.null {
					fmt.Fprint(w, "null")
					return
				}
				page := []any{}
				for n := first; n < min(first+100, test.count); n++ {
					page = append(page, map[string]any{"internalId": fmt.Sprintf("provider-%d", n), "alias": fmt.Sprintf("alias-%d", n), "providerId": "oidc", "enabled": true, "config": map[string]string{"issuer": "https://public.example.test"}})
				}
				writeAuthorizationJSON(w, page)
			}))
			defer s.Close()
			c := New(s.URL, "writer", "credential", WithInsecureHTTP())
			all, target, err := c.ObserveKubernetesWorkloadTrust(context.Background(), "managed", "absent")
			if test.name == "second page" {
				if err != nil || len(all) != 101 || target != nil {
					t.Fatal("native second page missed")
				}
			} else if err == nil || all != nil || target != nil {
				t.Fatal("partial read became qualified absence")
			}
		})
	}
}

func TestFederatedFlowGraphRejectsDisabledNestedCustomAndMissing(t *testing.T) {
	valid := []WorkloadFlowExecution{{ID: "fed", ProviderID: "federated-jwt", Requirement: "ALTERNATIVE"}, {ID: "secret", ProviderID: "client-secret", Requirement: "ALTERNATIVE"}}
	if !qualifiedFederatedExecutions(valid) {
		t.Fatal("native graph refused")
	}
	for _, change := range []func([]WorkloadFlowExecution){func(e []WorkloadFlowExecution) { e[0].Requirement = "DISABLED" }, func(e []WorkloadFlowExecution) { e[0].ProviderID = "client-jwt" }, func(e []WorkloadFlowExecution) { e[0].AuthenticationFlow = true }, func(e []WorkloadFlowExecution) { e[0].Level = 1 }, func(e []WorkloadFlowExecution) { e[0].FlowID = "nested" }, func(e []WorkloadFlowExecution) { e[1].ID = e[0].ID }, func(e []WorkloadFlowExecution) { e[1].ProviderID = "unknown" }, func(e []WorkloadFlowExecution) { e[1].ProviderID = "federated-jwt" }} {
		copy := append([]WorkloadFlowExecution(nil), valid...)
		change(copy)
		if qualifiedFederatedExecutions(copy) {
			t.Fatal("unsafe execution graph accepted")
		}
	}
}
