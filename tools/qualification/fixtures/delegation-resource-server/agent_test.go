package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func fixtureAgent(t *testing.T) (*agentFixture, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config := configuration{Issuer: "https://fixture/realms/software", Audience: "mcp-api",
		Resources: map[string]string{"/allowed": "invoice", "/denied": "foreign"}, Agentic: &agentConfiguration{
			A2AAudience: "a2a-api", A2AResource: "tasks", DownstreamAudience: "business-api", DownstreamResource: "business-invoice",
			ActorClient: "agent-b", ActorSubject: "actor-uuid", SubjectClient: "agent-a", SubjectSubject: "subject-uuid",
			ActorCredentials: "/missing/actor", SubjectCredentials: "/missing/subject", PublicURL: "https://fixture",
			ResourceName: "invoice", PolicyRevision: strings.Repeat("a", 64)}}
	f, err := newAgentFixture(verifier{config, map[string]*rsa.PublicKey{"native": &key.PublicKey}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.audit.writer = io.Discard
	return f, key
}

func signedAgentToken(t *testing.T, f *agentFixture, key *rsa.PrivateKey, change func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": f.resource.config.Issuer, "aud": "mcp-api", "exp": time.Now().Add(time.Minute).Unix(),
		"sub": "subject-uuid", "azp": "agent-b", "jti": "native-jti", "act": map[string]string{"sub": "actor-uuid", "client_id": "agent-b"},
		"authorization": map[string]any{"permissions": []any{map[string]any{"rsid": "invoice", "scopes": []string{"read"}}}}}
	if change != nil {
		change(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "native"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMCPRequiresExactAudienceActorOperationAndTrustedTask(t *testing.T) {
	f, key := fixtureAgent(t)
	for _, tc := range []struct {
		name, method, params string
		status               int
		proof                bool
		change               func(jwt.MapClaims)
	}{
		{"initialize", "initialize", `{}`, 200, true, nil},
		{"tools", "tools/list", `{}`, 200, true, nil},
		{"no-gateway", "tools/list", `{}`, 403, false, nil},
		{"wrong-tool", "tools/call", `{"name":"write_invoice","arguments":{}}`, 403, true, nil},
		{"tool-argument", "tools/call", `{"name":"read_invoice","arguments":{"scope":"write"}}`, 403, true, nil},
		{"missing-task", "tools/call", `{"name":"read_invoice","arguments":{}}`, 403, true, nil},
		{"forged-task", "tools/call", `{"name":"read_invoice","arguments":{}}`, 403, true, nil},
		{"wrong-audience", "initialize", `{}`, 401, true, func(c jwt.MapClaims) { c["aud"] = "a2a-api" }},
		{"downstream-audience", "initialize", `{}`, 401, true, func(c jwt.MapClaims) { c["aud"] = "business-api" }},
		{"wrong-issuer", "initialize", `{}`, 401, true, func(c jwt.MapClaims) { c["iss"] = "https://foreign" }},
		{"expired", "initialize", `{}`, 401, true, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Second).Unix() }},
		{"wrong-subject", "initialize", `{}`, 403, true, func(c jwt.MapClaims) { c["sub"] = "other" }},
		{"missing-actor", "initialize", `{}`, 403, true, func(c jwt.MapClaims) { delete(c, "act") }},
		{"wrong-current-actor", "initialize", `{}`, 403, true, func(c jwt.MapClaims) { c["act"] = map[string]string{"sub": "other", "client_id": "agent-b"} }},
		{"wrong-actor-client", "initialize", `{}`, 403, true, func(c jwt.MapClaims) { c["act"] = map[string]string{"sub": "actor-uuid", "client_id": "other"} }},
		{"wrong-resource", "initialize", `{}`, 403, true, func(c jwt.MapClaims) {
			c["authorization"] = map[string]any{"permissions": []any{map[string]any{"rsid": "foreign", "scopes": []string{"read"}}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := signedAgentToken(t, f, key, tc.change)
			r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+tc.method+`","params":`+tc.params+`}`))
			r.Header.Set("Authorization", "Bearer "+raw)
			r.Header.Set("MCP-Protocol-Version", "2025-11-25")
			if tc.proof {
				r.Header.Set("X-Fixture-Gateway", f.proof)
			}
			r.Header.Set("X-Fixture-Task", "caller-chosen-task")
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			if w.Code != tc.status || strings.Contains(w.Body.String(), raw) {
				t.Fatalf("unexpected %s decision: %d", tc.name, w.Code)
			}
		})
	}
}

func TestA2ACallerAndTaskPayloadCannotGrantAuthority(t *testing.T) {
	f, key := fixtureAgent(t)
	var audit bytes.Buffer
	f.audit.writer = &audit
	for _, payload := range []string{
		`{"message":{"messageId":"one","role":"ROLE_USER","parts":[{"text":"read"}],"taskId":"spoofed"}}`,
		`{"message":{"messageId":"one","role":"ROLE_USER","parts":[{"text":"read"}]},"agentCard":{"grant":"admin"}}`,
		`{"message":{"messageId":"one","role":"ROLE_USER","parts":[{"text":"read"}]} , "message":{}}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/message:send", strings.NewReader(payload))
		raw := signedAgentToken(t, f, key, func(c jwt.MapClaims) {
			c["aud"] = "a2a-api"
			c["azp"] = "agent-a"
			delete(c, "act")
			c["authorization"] = map[string]any{"permissions": []any{map[string]any{"rsid": "tasks", "scopes": []string{"invoke"}}}}
		})
		r.Header.Set("Authorization", "Bearer "+raw)
		r.Header.Set("A2A-Version", "1.0")
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != 400 || strings.Contains(audit.String(), raw) || strings.Contains(audit.String(), "spoofed") {
			t.Fatal("caller supplied task authority or private telemetry accepted")
		}
	}
	for _, path := range []string{"/downstream", "/message:send"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+signedAgentToken(t, f, key, nil))
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("cross-audience direct bypass accepted")
		}
	}
}

type failedAuditWriter struct{}

func TestTaskOptInCannotAcceptAnUnboundSignedToken(t *testing.T) {
	f, key := fixtureAgent(t)
	f.config.TaskAuthorization = &taskConfiguration{AuthorityClient: "trusted-issuer", AudienceID: "native-mcp", Grant: "read"}
	task := &taskAssignment{id: "assignment", jti: "native-jti", nativeContext: strings.Repeat("c", 64), expires: time.Now().Add(time.Minute).Unix()}
	// A perfectly valid software token remains insufficient for a task-required receiver.
	raw := signedAgentToken(t, f, key, nil)
	claims, err := f.resource.claims(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.checkTask(t.Context(), task, claims) == nil {
		t.Fatal("task receiver accepted an unbound software token")
	}
	claims[taskClaim] = map[string]any{"version": float64(1), "reference": task.nativeContext, "parametersHash": operationHash(), "policyRevision": f.config.PolicyRevision}
	for key, wrong := range map[string]any{"version": float64(2), "reference": strings.Repeat("d", 64), "parametersHash": strings.Repeat("e", 64), "policyRevision": strings.Repeat("f", 64)} {
		value := claims[taskClaim].(map[string]any)
		previous := value[key]
		value[key] = wrong
		if f.checkTask(t.Context(), task, claims) == nil {
			t.Fatal("task receiver accepted a substituted signed binding")
		}
		value[key] = previous
	}
}

func (failedAuditWriter) Write([]byte) (int, error) { return 0, errors.New("collector unavailable") }

func TestAuditOutageAndUntrustedAttributesCannotCreateEvidence(t *testing.T) {
	audit := newAgentAudit()
	var output bytes.Buffer
	audit.writer = &output
	trace, revision := strings.Repeat("a", 32), strings.Repeat("b", 64)
	if !audit.record(trace, "mcp", "deny", revision) {
		t.Fatal("bounded denial missing")
	}
	for _, value := range []string{"Bearer private-token", "agent-private-prompt", "native-user-id"} {
		if audit.record(trace, value, "allow", revision) || audit.record(value, "mcp", "allow", revision) || strings.Contains(output.String(), value) {
			t.Fatal("untrusted telemetry accepted")
		}
	}
	audit.writer = failedAuditWriter{}
	if audit.record(trace, "mcp", "allow", revision) {
		t.Fatal("collector outage reported complete evidence")
	}
}

func TestOTLPDecisionsCorrelateAndCollectorOutageIsIncomplete(t *testing.T) {
	f, _ := fixtureAgent(t)
	server := httptest.NewTLSServer(f)
	defer server.Close()
	f.config.PublicURL = server.URL
	f.client = server.Client()
	f.audit.export = func(record auditRecord) bool { return f.exportTrace(record) }
	var output bytes.Buffer
	f.audit.writer = &output
	trace, revision := strings.Repeat("c", 32), strings.Repeat("b", 64)
	for _, stage := range []string{"a2a", "exchange", "mcp"} {
		if !f.audit.record(trace, stage, "allow", revision) {
			t.Fatal("verified TLS OTLP export failed")
		}
	}
	decoder := json.NewDecoder(&output)
	var prior string
	for range 3 {
		var record auditRecord
		if decoder.Decode(&record) != nil || record.Coverage != "exported" || record.Trace != trace || record.Parent != prior {
			t.Fatal("trace lineage or export acknowledgement lost")
		}
		prior = record.Span
	}
	f.config.QualificationProbe = "collector-outage"
	if f.audit.record(trace, "task", "deny", revision) {
		t.Fatal("collector outage reported complete coverage")
	}
	var missing auditRecord
	if json.NewDecoder(&output).Decode(&missing) != nil || missing.Coverage != "incomplete" {
		t.Fatal("collector loss was not exposed locally")
	}
}
