package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
	"github.com/golang-jwt/jwt/v5"
)

// All configuration comes from the fixture administrator. Agent Cards, message
// text, tool arguments and caller task IDs never supply these bindings.
type agentConfiguration struct {
	A2AAudience        string             `json:"a2aAudience"`
	A2AResource        string             `json:"a2aResource"`
	DownstreamAudience string             `json:"downstreamAudience"`
	DownstreamResource string             `json:"downstreamResource"`
	ActorClient        string             `json:"actorClient"`
	ActorSubject       string             `json:"actorSubject"`
	SubjectClient      string             `json:"subjectClient"`
	SubjectSubject     string             `json:"subjectSubject"`
	ActorCredentials   string             `json:"actorCredentials"`
	SubjectCredentials string             `json:"subjectCredentials"`
	PublicURL          string             `json:"publicURL"`
	ResourceName       string             `json:"resourceName"`
	PolicyRevision     string             `json:"policyRevision"`
	QualificationProbe string             `json:"qualificationProbe,omitempty"`
	TaskAuthorization  *taskConfiguration `json:"taskAuthorization,omitempty"`
}

type taskAssignment struct {
	id, jti, trace string
	expires        int64
	consumed       bool
	nativeContext  string
}

type agentFixture struct {
	resource verifier
	config   agentConfiguration
	client   *http.Client
	proof    string
	mu       sync.Mutex
	tasks    map[string]*taskAssignment
	audit    *agentAudit
}

type rpcRequest struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

var errQualificationConfiguration = errors.New("qualification precondition failed")

type fixtureTrace struct{}

func randomReference(size int) string {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		panic("fixture randomness unavailable")
	}
	return hex.EncodeToString(value)
}

func newAgentFixture(resource verifier, client *http.Client) (*agentFixture, error) {
	c := *resource.config.Agentic
	if !validAgentEndpoint(c, resource.config.Audience) || !validAgentIdentities(c) || !validAgentResources(c, resource) || !validAgentTask(c, resource.config.Audience) {
		return nil, errors.New("fixture agent authority configuration refused")
	}
	switch c.QualificationProbe {
	case "", "wrong-tool", "wrong-scope", "foreign-resource", "missing-gateway", "foreign-task", "spent-task", "expired", "collector-outage", "cancelled-task", "invalid-approval", "approval-replay":
	default:
		return nil, errors.New("unknown qualification fault")
	}
	audit := newAgentAudit()
	audit.bindings(c.ActorClient+":"+c.ActorSubject, c.SubjectClient+":"+c.SubjectSubject, resource.config.Issuer+":"+resource.config.Audience)
	fixture := &agentFixture{resource: resource, config: c, client: client, proof: randomReference(32), tasks: map[string]*taskAssignment{}, audit: audit}
	if client != nil {
		audit.export = func(record auditRecord) bool { return fixture.exportTrace(record) }
	}
	return fixture, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *agentFixture) authenticate(r *http.Request, audience string) (jwt.MapClaims, error) {
	header := r.Header.Values("Authorization")
	if len(header) != 1 || !strings.HasPrefix(header[0], "Bearer ") || len(header[0]) > 65536 {
		return nil, errors.New("authentication required")
	}
	v := f.resource
	v.config.Audience = audience
	return v.claims(strings.TrimPrefix(header[0], "Bearer "))
}

func (f *agentFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != f.config.PublicURL {
		writeJSON(w, 403, map[string]string{"error": "origin_refused"})
		return
	}
	switch r.URL.Path {
	case "/v1/traces":
		f.collectTrace(w, r)
	case "/.well-known/oauth-protected-resource/mcp":
		writeJSON(w, 200, map[string]any{"resource": f.config.PublicURL + "/mcp", "authorization_servers": []string{f.resource.config.Issuer}, "bearer_methods_supported": []string{"header"}})
	case "/message:send":
		f.a2a(w, r)
	case "/mcp":
		f.mcp(w, r)
	case "/downstream":
		claims, err := f.authenticate(r, f.config.DownstreamAudience)
		if err != nil || claims["sub"] != f.config.ActorSubject || claims["azp"] != f.config.ActorClient ||
			!allowedPermission(claims, f.config.DownstreamResource, "read") || r.Method != http.MethodGet ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Fixture-Gateway")), []byte(f.proof)) != 1 {
			writeJSON(w, 403, map[string]string{"error": "downstream_refused"})
			return
		}
		writeJSON(w, 200, map[string]string{"invoice": "synthetic-read-only"})
	default:
		writeJSON(w, 404, map[string]string{"error": "unknown_resource"})
	}
}

func decodeRequest(r *http.Request, value any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(data) > 16384 || httpsecurity.ValidateJSON(data) != nil {
		return errors.New("request limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("request refused")
	}
	return nil
}

func (f *agentFixture) a2a(w http.ResponseWriter, r *http.Request) {
	trace := randomReference(16)
	claims, err := f.authenticate(r, f.config.A2AAudience)
	if r.Method != http.MethodPost || r.Header.Get("A2A-Version") != "1.0" || err != nil ||
		claims["sub"] != f.config.SubjectSubject || claims["azp"] != f.config.SubjectClient ||
		!allowedPermission(claims, f.config.A2AResource, "invoke") {
		f.audit.record(trace, "a2a", "deny", f.config.PolicyRevision)
		writeJSON(w, 403, map[string]string{"error": "task_assignment_refused"})
		return
	}
	if !validA2AMessage(r) {
		writeJSON(w, 400, map[string]string{"error": "task_input_refused"})
		return
	}
	// Assignment exists only after ingress authentication. It is created outside
	// the agent workspace and never reconstructed from a supplied task ID.
	task := f.newAssignment(trace)
	if task == nil {
		writeJSON(w, 503, map[string]string{"error": "task_capacity"})
		return
	}
	defer func() { f.mu.Lock(); delete(f.tasks, task.id); f.mu.Unlock() }()
	if !f.audit.record(trace, "a2a", "allow", f.config.PolicyRevision) {
		writeJSON(w, 503, map[string]string{"error": "audit_unavailable"})
		return
	}
	if err := f.execute(r.Context(), task); err != nil {
		f.audit.record(trace, "task", "deny", f.config.PolicyRevision)
		if errors.Is(err, errQualificationConfiguration) {
			writeJSON(w, 500, map[string]string{"error": "qualification_precondition_failed"})
			return
		}
		writeJSON(w, 403, map[string]string{"error": "bounded_task_refused"})
		return
	}
	if !f.audit.record(trace, "task", "allow", f.config.PolicyRevision) {
		writeJSON(w, 503, map[string]string{"error": "audit_unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"task": map[string]any{"id": task.id, "contextId": trace,
		"status": map[string]string{"state": "TASK_STATE_COMPLETED"}, "artifacts": []any{map[string]any{
			"artifactId": randomReference(16), "parts": []any{map[string]string{"text": "synthetic-read-only"}}}}}})
}

func (f *agentFixture) mcp(w http.ResponseWriter, r *http.Request) {
	trace := randomReference(16)
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Fixture-Gateway")), []byte(f.proof)) == 1 {
		f.mu.Lock()
		if task := f.tasks[r.Header.Get("X-Fixture-Task")]; task != nil {
			trace = task.trace
		}
		f.mu.Unlock()
	}
	writer := &decisionWriter{ResponseWriter: w, status: 200}
	defer func() {
		if writer.status >= 400 {
			f.audit.record(trace, "mcp", "deny", f.config.PolicyRevision)
		}
	}()
	f.handleMCP(writer, r)
}

type decisionWriter struct {
	http.ResponseWriter
	status int
}

func (w *decisionWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (f *agentFixture) handleMCP(w http.ResponseWriter, r *http.Request) {
	claims, err := f.authenticate(r, f.resource.config.Audience)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+f.config.PublicURL+`/.well-known/oauth-protected-resource/mcp"`)
		writeJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	if !f.hasMCPAuthority(r, claims) {
		writeJSON(w, 403, map[string]string{"error": "mcp_authority_refused"})
		return
	}
	request, valid := readMCPRequest(w, r)
	if !valid {
		return
	}
	result := map[string]any{}
	switch request.Method {
	case "initialize":
		result = map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]string{"name": "bounded-fixture", "version": "1.1.0"}}
	case "tools/list":
		result["tools"] = []any{map[string]any{"name": "read_invoice", "description": "Read the synthetic invoice", "inputSchema": map[string]any{
			"type": "object", "properties": map[string]any{}, "additionalProperties": false}}}
	case "tools/call":
		if !f.invokeMCPTool(w, r, claims, request.Params) {
			return
		}
		result["content"] = []any{map[string]string{"type": "text", "text": "synthetic-read-only"}}
	default:
		writeJSON(w, 403, map[string]string{"error": "method_refused"})
		return
	}
	writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
}

// No token retry is performed here. A lost response may have consumed the actor
// JTI. A new authenticated task obtains independent, fresh actor evidence.
func (f *agentFixture) execute(ctx context.Context, task *taskAssignment) error {
	return f.exchangeAndInvoke(context.WithValue(ctx, fixtureTrace{}, task.trace), task)
}

func validAgentEndpoint(c agentConfiguration, audience string) bool {
	endpoint, err := url.Parse(c.PublicURL)
	return err == nil && endpoint.Scheme == "https" && endpoint.Host != "" && endpoint.User == nil && endpoint.RawQuery == "" &&
		endpoint.Fragment == "" && endpoint.Path == "" && c.A2AAudience != "" && c.DownstreamAudience != "" &&
		c.A2AAudience != audience && c.DownstreamAudience != audience && c.DownstreamAudience != c.A2AAudience
}
func validAgentIdentities(c agentConfiguration) bool {
	return c.ActorClient != "" && c.SubjectClient != "" && c.ActorClient != c.SubjectClient && c.ActorSubject != "" &&
		c.SubjectSubject != "" && c.ActorSubject != c.SubjectSubject && c.ActorCredentials != "" && c.SubjectCredentials != ""
}
func validAgentResources(c agentConfiguration, resource verifier) bool {
	return c.A2AResource != "" && c.DownstreamResource != "" && resource.config.Resources["/allowed"] != "" &&
		c.ResourceName != "" && len(c.ResourceName) <= 128 && policyReference.MatchString(c.PolicyRevision)
}
func validAgentTask(c agentConfiguration, audience string) bool {
	task := c.TaskAuthorization
	return task == nil || task.AuthorityClient != "" && task.AuthorityClient != c.ActorClient && task.AuthorityClient != c.SubjectClient &&
		task.AuthorityClient != audience && task.AuthorityCredentials != "" && task.RecipientCredentials != "" && task.AudienceID != "" && task.Grant != ""
}
func validA2AMessage(r *http.Request) bool {
	var request struct {
		Message struct {
			ID    string `json:"messageId"`
			Role  string `json:"role"`
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"message"`
	}
	if decodeRequest(r, &request) != nil || request.Message.ID == "" || len(request.Message.ID) > 128 ||
		request.Message.Role != "ROLE_USER" || len(request.Message.Parts) != 1 || len(request.Message.Parts[0].Text) > 1024 {
		return false
	}
	return true
}

func (f *agentFixture) newAssignment(trace string) *taskAssignment {
	task := &taskAssignment{id: randomReference(16), trace: trace, expires: time.Now().Add(30 * time.Second).Unix()}
	f.mu.Lock()
	for id, previous := range f.tasks {
		if previous.expires < time.Now().Unix() || previous.consumed {
			delete(f.tasks, id)
		}
	}
	if len(f.tasks) >= 128 {
		f.mu.Unlock()
		return nil
	}
	f.tasks[task.id] = task
	f.mu.Unlock()
	return task
}

func (f *agentFixture) invokeMCPTool(w http.ResponseWriter, r *http.Request, claims jwt.MapClaims, paramsJSON json.RawMessage) bool {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(paramsJSON)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&params) != nil || params.Name != "read_invoice" || len(params.Arguments) != 0 {
		writeJSON(w, 403, map[string]string{"error": "tool_refused"})
		return false
	}
	f.mu.Lock()
	task := f.tasks[r.Header.Get("X-Fixture-Task")]
	valid := task != nil && !task.consumed && task.jti == claims["jti"] && task.expires > time.Now().Unix()
	if valid {
		task.consumed = true
	}
	f.mu.Unlock()
	if valid && f.config.TaskAuthorization != nil {
		valid = f.checkTask(r.Context(), task, claims) == nil
	}
	if !valid || !f.audit.record(task.trace, "mcp", "allow", f.config.PolicyRevision) {
		writeJSON(w, 403, map[string]string{"error": "task_context_refused"})
		return false
	}
	if err := f.downstream(r.Context(), task.trace); err != nil {
		writeJSON(w, 403, map[string]string{"error": "downstream_refused"})
		return false
	}
	return true
}

func (f *agentFixture) hasMCPAuthority(r *http.Request, claims jwt.MapClaims) bool {
	actor, _ := claims["act"].(map[string]any)
	return claims["sub"] == f.config.SubjectSubject && claims["azp"] == f.config.ActorClient && actor["sub"] == f.config.ActorSubject && actor["client_id"] == f.config.ActorClient &&
		allowedPermission(claims, f.resource.config.Resources["/allowed"], "read") &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Fixture-Gateway")), []byte(f.proof)) == 1
}
func readMCPRequest(w http.ResponseWriter, r *http.Request) (rpcRequest, bool) {
	if r.Method != http.MethodPost || r.Header.Get("MCP-Protocol-Version") != "2025-11-25" {
		w.Header().Set("Allow", "POST")
		writeJSON(w, 405, map[string]string{"error": "transport_refused"})
		return rpcRequest{}, false
	}
	var request rpcRequest
	if decodeRequest(r, &request) != nil || request.Version != "2.0" || len(request.ID) > 128 {
		writeJSON(w, 400, map[string]string{"error": "rpc_refused"})
		return rpcRequest{}, false
	}
	if request.Method == "notifications/initialized" && len(request.ID) == 0 {
		w.WriteHeader(202)
		return rpcRequest{}, false
	}
	var id any
	if json.Unmarshal(request.ID, &id) != nil || id == nil {
		writeJSON(w, 400, map[string]string{"error": "rpc_id_required"})
		return rpcRequest{}, false
	}
	switch id.(type) {
	case string, float64:
	default:
		writeJSON(w, 400, map[string]string{"error": "rpc_id_refused"})
		return rpcRequest{}, false
	}
	return request, true
}
