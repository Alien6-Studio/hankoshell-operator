package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// This is protocol-unit evidence with a synthetic signed-token endpoint. Real
// Keycloak policy, replay and cluster conformance have separate native/installed suites.
type protocolLab struct {
	mu                  sync.Mutex
	t                   *testing.T
	f                   *agentFixture
	key                 *rsa.PrivateKey
	secrets             map[string]string
	subjects            map[string]string
	tokens              []string
	used                map[string]bool
	approval, reference string
	active              bool
	fault               string
	exchanges, backend  int
}

func newProtocolLab(t *testing.T, task bool, probe, fault string) (*protocolLab, *httptest.Server, *bytes.Buffer) {
	t.Helper()
	f, key := fixtureAgent(t)
	lab := &protocolLab{t: t, f: f, key: key, secrets: map[string]string{}, subjects: map[string]string{
		"agent-a": "subject-uuid", "agent-b": "actor-uuid", "task-authority": "issuer-uuid", "mcp-api": "recipient-uuid"}, used: map[string]bool{}, fault: fault}
	directory := t.TempDir()
	credential := func(client string) string {
		secret := randomReference(32)
		lab.secrets[client] = secret
		secretFile := filepath.Join(directory, client+".secret")
		if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(map[string]string{"client_id": client, "client_secret_path": secretFile})
		file := filepath.Join(directory, client+".json")
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	f.config.ActorCredentials = credential("agent-b")
	f.config.SubjectCredentials = credential("agent-a")
	if task {
		f.config.TaskAuthorization = &taskConfiguration{AuthorityClient: "task-authority", AuthorityCredentials: credential("task-authority"),
			RecipientCredentials: credential("mcp-api"), AudienceID: "native-mcp", Grant: "read"}
	}
	f.config.QualificationProbe = probe
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/software/protocol/openid-connect/token" || strings.HasPrefix(r.URL.Path, "/realms/software/bounded-delegation/task-context") {
			lab.native(w, r)
			return
		}
		if r.URL.Path == "/downstream" {
			lab.mu.Lock()
			lab.backend++
			lab.mu.Unlock()
			if fault == "downstream" {
				writeJSON(w, 403, map[string]string{})
				return
			}
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	f.resource.config.Issuer = server.URL + "/realms/software"
	f.config.PublicURL = server.URL
	f.client = server.Client()
	f.client.Timeout = 5 * time.Second
	var audit bytes.Buffer
	f.audit.writer = &audit
	f.audit.export = func(record auditRecord) bool { return f.exportTrace(record) }
	return lab, server, &audit
}

func (lab *protocolLab) signed(client, audience, resource string, delegated bool) string {
	raw := signedAgentToken(lab.t, lab.f, lab.key, func(c jwt.MapClaims) {
		c["azp"], c["sub"], c["aud"], c["jti"] = client, lab.subjects[client], audience, randomReference(16)
		c["exp"] = time.Now().Add(time.Minute).Unix()
		delete(c, "act")
		c["authorization"] = map[string]any{"permissions": []any{map[string]any{"rsid": resource, "scopes": []string{"read"}}}}
		if delegated {
			c["sub"] = lab.f.config.SubjectSubject
			c["act"] = map[string]string{"sub": lab.f.config.ActorSubject, "client_id": lab.f.config.ActorClient}
			if lab.f.config.QualificationProbe == "expired" {
				c["exp"] = time.Now().Add(time.Second).Unix()
			}
			if lab.f.config.TaskAuthorization != nil {
				c[taskClaim] = map[string]any{"version": 1, "reference": lab.reference, "parametersHash": operationHash(), "policyRevision": lab.f.config.PolicyRevision}
			}
		}
	})
	lab.tokens = append(lab.tokens, raw)
	return raw
}

func (lab *protocolLab) bearer(r *http.Request, audience string) jwt.MapClaims {
	v := lab.f.resource
	v.config.Audience = audience
	c, err := v.claims(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil {
		return nil
	}
	return c
}

func (lab *protocolLab) native(w http.ResponseWriter, r *http.Request) {
	lab.mu.Lock()
	defer lab.mu.Unlock()
	if strings.Contains(r.URL.Path, "/task-context") {
		lab.taskAPI(w, r)
		return
	}
	if lab.fault == "token" {
		writeJSON(w, 503, map[string]string{})
		return
	}
	if r.ParseForm() != nil {
		writeJSON(w, 400, map[string]string{})
		return
	}
	client := r.Form.Get("client_id")
	switch r.Form.Get("grant_type") {
	case "client_credentials":
		if lab.secrets[client] == "" || r.Form.Get("client_secret") != lab.secrets[client] {
			writeJSON(w, 401, map[string]string{})
			return
		}
		audience := "input"
		if client == "task-authority" || client == "mcp-api" {
			audience = taskEndpointAudience
		}
		writeJSON(w, 200, map[string]string{"access_token": lab.signed(client, audience, "unused", false)})
	case "urn:ietf:params:oauth:grant-type:uma-ticket":
		c := lab.bearer(r, "input")
		if c == nil {
			writeJSON(w, 401, map[string]string{})
			return
		}
		client, _ = c["azp"].(string)
		audience := r.Form.Get("audience")
		resource := lab.f.resource.config.Resources["/allowed"]
		if audience == lab.f.config.DownstreamAudience {
			resource = lab.f.config.DownstreamResource
		}
		writeJSON(w, 200, map[string]string{"access_token": lab.signed(client, audience, resource, false)})
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		lab.exchanges++
		v := lab.f.resource
		actor, err := v.claims(r.Form.Get("actor_token"))
		if err != nil || actor["azp"] != client || r.Form.Get("client_secret") != lab.secrets[client] {
			writeJSON(w, 400, map[string]string{})
			return
		}
		jti, _ := actor["jti"].(string)
		if lab.used[jti] || (lab.f.config.TaskAuthorization != nil && r.Form.Get("task_context") != lab.approval) {
			writeJSON(w, 400, map[string]string{})
			return
		}
		lab.used[jti] = true
		token := lab.signed(client, lab.f.resource.config.Audience, lab.f.resource.config.Resources["/allowed"], true)
		if lab.fault == "lost-response" {
			socket, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				lab.t.Error("unit transport could not close response")
				return
			}
			_ = socket.Close()
			return
		}
		writeJSON(w, 200, map[string]string{"access_token": token})
	default:
		writeJSON(w, 400, map[string]string{})
	}
}

func (lab *protocolLab) taskAPI(w http.ResponseWriter, r *http.Request) {
	c := lab.bearer(r, taskEndpointAudience)
	if c == nil {
		writeJSON(w, 403, map[string]string{})
		return
	}
	client, _ := c["azp"].(string)
	if strings.HasSuffix(r.URL.Path, "/contexts") && r.Method == http.MethodPost && client == "task-authority" {
		var registration map[string]any
		if json.NewDecoder(r.Body).Decode(&registration) != nil || registration["parametersHash"] != operationHash() {
			writeJSON(w, 400, map[string]string{})
			return
		}
		lab.reference, lab.approval, lab.active = randomReference(32), randomReference(32), true
		writeJSON(w, 201, map[string]any{"reference": lab.reference, "approval": lab.approval, "expiresAt": time.Now().Add(20 * time.Second).Unix()})
		return
	}
	if r.Method == http.MethodDelete && client == "task-authority" {
		lab.active = false
		writeJSON(w, 200, map[string]bool{"cancelled": true})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/check") && client == "mcp-api" {
		if lab.fault == "online" {
			writeJSON(w, 503, map[string]string{})
			return
		}
		if !lab.active {
			writeJSON(w, 403, map[string]string{})
			return
		}
		writeJSON(w, 200, map[string]bool{"active": true})
		return
	}
	writeJSON(w, 403, map[string]string{})
}

func TestAgentProtocolFreshEvidenceFailuresAndOnlineEnforcement(t *testing.T) {
	for _, tc := range []struct {
		name, probe, fault string
		task               bool
		status, backend    int
	}{
		{name: "software success", status: 200, backend: 1},
		{name: "task success", task: true, status: 200, backend: 1},
		{name: "tool", probe: "wrong-tool", status: 403},
		{name: "scope", probe: "wrong-scope", status: 403},
		{name: "resource", probe: "foreign-resource", status: 403},
		{name: "gateway", probe: "missing-gateway", status: 403},
		{name: "foreign task", probe: "foreign-task", status: 403},
		{name: "spent task", probe: "spent-task", status: 403, backend: 1},
		{name: "expiry", probe: "expired", status: 403},
		{name: "collector", probe: "collector-outage", status: 503},
		{name: "cancelled", task: true, probe: "cancelled-task", status: 403},
		{name: "approval", task: true, probe: "invalid-approval", status: 403},
		{name: "approval replay", task: true, probe: "approval-replay", status: 403},
		{name: "token outage", fault: "token", status: 403},
		{name: "online outage", task: true, fault: "online", status: 403},
		{name: "lost response", fault: "lost-response", status: 403},
		{name: "backend refusal", fault: "downstream", status: 403, backend: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lab, server, audit := newProtocolLab(t, tc.task, tc.probe, tc.fault)
			token := signedAgentToken(t, lab.f, lab.key, func(c jwt.MapClaims) {
				c["aud"], c["azp"] = lab.f.config.A2AAudience, lab.f.config.SubjectClient
				delete(c, "act")
				c["authorization"] = map[string]any{"permissions": []any{map[string]any{"rsid": lab.f.config.A2AResource, "scopes": []string{"invoke"}}}}
			})
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/message:send", strings.NewReader(`{"message":{"messageId":"unit-message","role":"ROLE_USER","parts":[{"text":"synthetic"}]}}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("A2A-Version", "1.0")
			response, err := lab.f.client.Do(request)
			if err != nil {
				t.Fatal("protocol unit transport failed")
			}
			_ = response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("status %d, expected %d", response.StatusCode, tc.status)
			}
			lab.mu.Lock()
			defer lab.mu.Unlock()
			if lab.backend != tc.backend {
				t.Fatalf("backend effects %d, expected %d", lab.backend, tc.backend)
			}
			if tc.fault == "lost-response" && lab.exchanges != 1 {
				t.Fatal("uncertain native response retried actor evidence")
			}
			for _, secret := range lab.secrets {
				if strings.Contains(audit.String(), secret) {
					t.Fatal("credential in audit")
				}
			}
			for _, raw := range lab.tokens {
				if strings.Contains(audit.String(), raw) {
					t.Fatal("bearer in audit")
				}
			}
			if lab.reference != "" && (strings.Contains(audit.String(), lab.reference) || strings.Contains(audit.String(), lab.approval)) {
				t.Fatal("task proof in audit")
			}
		})
	}
}
