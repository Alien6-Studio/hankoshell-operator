package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

// Credential files belong to the trusted fixture workload, outside agent
// writable storage. Projected Kubernetes assertions and client secrets are read
// only for OAuth requests and are never returned to A2A/MCP callers.
type fixtureCredentials struct {
	ClientID      string `json:"client_id"`
	Secret        string `json:"client_secret,omitempty"`
	SecretPath    string `json:"client_secret_path,omitempty"`
	AssertionPath string `json:"client_assertion_path,omitempty"`
}

func (f *agentFixture) token(ctx context.Context, fields url.Values, bearer string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.resource.config.Issuer+"/protocol/openid-connect/token", strings.NewReader(fields.Encode()))
	if err != nil {
		return "", errors.New("fixture token request refused")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if trace, ok := ctx.Value(fixtureTrace{}).(string); ok {
		request.Header.Set("traceparent", f.audit.traceparent(trace))
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := f.client.Do(request)
	if err != nil {
		return "", errors.New("fixture token transport unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 || response.StatusCode != 200 {
		return "", errors.New("fixture native token refused")
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(data, &body) != nil || body.AccessToken == "" || body.RefreshToken != "" {
		return "", errors.New("fixture native token refused")
	}
	return body.AccessToken, nil
}

func credentials(path, expectedClient string) (url.Values, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 8192 {
		return nil, errors.New("fixture workload credentials unavailable")
	}
	var value fixtureCredentials
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.ClientID != expectedClient {
		return nil, errors.New("fixture workload credentials refused")
	}
	methods := 0
	for _, method := range []string{value.Secret, value.SecretPath, value.AssertionPath} {
		if method != "" {
			methods++
		}
	}
	if methods != 1 {
		return nil, errors.New("fixture workload authentication ambiguous")
	}
	if value.SecretPath != "" {
		secret, err := readFixtureCredential(value.SecretPath, 8192)
		if err != nil {
			return nil, errors.New("fixture workload secret unavailable")
		}
		value.Secret = secret
	}
	fields := url.Values{"client_id": {value.ClientID}}
	if value.Secret != "" {
		fields.Set("client_secret", value.Secret)
	} else {
		assertion, err := readFixtureCredential(value.AssertionPath, 16384)
		if err != nil {
			return nil, errors.New("fixture workload assertion unavailable")
		}
		fields.Set("client_assertion", assertion)
		fields.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	}
	return fields, nil
}

func (f *agentFixture) input(ctx context.Context, path, client, subject, audience, resource string) (string, error) {
	fields, err := credentials(path, client)
	if err != nil {
		return "", err
	}
	fields.Set("grant_type", "client_credentials")
	access, err := f.token(ctx, fields, "")
	if err != nil {
		return "", err
	}
	input, err := f.token(ctx, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:uma-ticket"},
		"audience": {audience}, "permission": {resource + "#read"}}, access)
	if err != nil {
		return "", err
	}
	v := f.resource
	v.config.Audience = audience
	claims, err := v.claims(input)
	if err != nil || claims["sub"] != subject || claims["azp"] != client || claims["act"] != nil {
		return "", errors.New("fixture fresh workload identity refused")
	}
	return input, nil
}

func (f *agentFixture) exchangeAndInvoke(ctx context.Context, task *taskAssignment) error {
	delegated, expiry, err := f.exchangeTask(ctx, task)
	if err != nil {
		f.audit.record(task.trace, "exchange", "deny", f.config.PolicyRevision)
		return err
	}
	if !f.audit.record(task.trace, "exchange", "allow", f.config.PolicyRevision) {
		return errors.New("fixture audit unavailable")
	}
	if err := f.qualificationPrelude(ctx, task, expiry); err != nil {
		return err
	}
	return f.invokeMCP(ctx, task, delegated)
}
func (f *agentFixture) exchangeTask(ctx context.Context, task *taskAssignment) (string, int64, error) {
	actor, err := f.input(ctx, f.config.ActorCredentials, f.config.ActorClient, f.config.ActorSubject, f.resource.config.Audience, f.config.ResourceName)
	if err != nil {
		return "", 0, err
	}
	subject, err := f.input(ctx, f.config.SubjectCredentials, f.config.SubjectClient, f.config.SubjectSubject, f.resource.config.Audience, f.config.ResourceName)
	if err != nil {
		return "", 0, err
	}
	fields, err := credentials(f.config.ActorCredentials, f.config.ActorClient)
	if err != nil {
		return "", 0, err
	}
	for key, value := range map[string]string{"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": subject, "subject_token_type": accessTokenType, "actor_token": actor, "actor_token_type": accessTokenType,
		"audience": f.resource.config.Audience} {
		fields.Set(key, value)
	}
	if err := f.approveTask(ctx, task, fields, actor, subject); err != nil {
		return "", 0, err
	}
	delegated, err := f.token(ctx, fields, "")
	if err != nil {
		return "", 0, err
	}
	if f.config.QualificationProbe == "approval-replay" {
		delegated, err = f.token(ctx, fields, "")
		if err != nil {
			return "", 0, err
		}
	}
	claims, err := f.resource.claims(delegated)
	if err != nil {
		return "", 0, errors.New("fixture delegated token verification failed")
	}
	jti, _ := claims["jti"].(string)
	expiry, err := claims.GetExpirationTime()
	if err != nil || expiry == nil || jti == "" {
		return "", 0, errors.New("fixture delegated token binding unavailable")
	}
	f.mu.Lock()
	task.jti, task.expires = jti, min(expiry.Unix(), time.Now().Add(30*time.Second).Unix())
	f.mu.Unlock()
	return delegated, expiry.Unix(), nil
}
func (f *agentFixture) qualificationPrelude(ctx context.Context, task *taskAssignment, expiry int64) error {
	if f.config.QualificationProbe == "cancelled-task" {
		if f.config.TaskAuthorization == nil {
			return errQualificationConfiguration
		}
		if _, err := f.taskRequest(ctx, http.MethodDelete, "/contexts/"+task.nativeContext, nil, true, 200); err != nil {
			return errQualificationConfiguration
		}
	}
	if f.config.QualificationProbe == "expired" {
		delay := time.Until(time.Unix(expiry+1, 0))
		if delay > 5*time.Second {
			return errQualificationConfiguration
		}
		if delay > 0 {
			select {
			case <-ctx.Done():
				return errors.New("expiry qualification interrupted")
			case <-time.After(delay):
			}
		}
	}
	return nil
}
func (f *agentFixture) invokeMCP(ctx context.Context, task *taskAssignment, delegated string) error {
	initialized, err := f.mcpRequest(ctx, task, delegated, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"trusted-fixture","version":"1.1.0"}}}`, 200)
	if err != nil {
		return err
	}
	var negotiation struct {
		Result struct {
			Version string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(initialized, &negotiation) != nil || negotiation.Result.Version != "2025-11-25" {
		return errors.New("fixture MCP negotiation refused")
	}
	if _, err := f.mcpRequest(ctx, task, delegated, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202); err != nil {
		return err
	}
	toolCall := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_invoice","arguments":{}}}`
	switch f.config.QualificationProbe {
	case "wrong-tool":
		toolCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_invoice","arguments":{}}}`
	case "wrong-scope":
		toolCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_invoice","arguments":{"scope":"write"}}}`
	case "foreign-resource":
		toolCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_invoice","arguments":{"resource":"foreign-invoice"}}}`
	}
	data, err := f.mcpRequest(ctx, task, delegated, toolCall, 200)
	if err != nil {
		return err
	}
	if f.config.QualificationProbe == "spent-task" {
		_, err := f.mcpRequest(ctx, task, delegated, toolCall, 200)
		return err
	}
	var body struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &body) != nil || len(body.Result.Content) != 1 || body.Result.Content[0].Text != "synthetic-read-only" {
		return errors.New("fixture MCP result refused")
	}
	return nil
}

func (f *agentFixture) mcpRequest(ctx context.Context, task *taskAssignment, delegated, body string, status int) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.config.PublicURL+"/mcp",
		strings.NewReader(body))
	if err != nil {
		return nil, errors.New("fixture MCP request refused")
	}
	request.Header.Set("Authorization", "Bearer "+delegated)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-11-25")
	request.Header.Set("X-Fixture-Gateway", f.proof)
	request.Header.Set("X-Fixture-Task", task.id)
	if f.config.QualificationProbe == "missing-gateway" {
		request.Header.Del("X-Fixture-Gateway")
	}
	if f.config.QualificationProbe == "foreign-task" {
		request.Header.Set("X-Fixture-Task", randomReference(16))
	}
	request.Header.Set("traceparent", f.audit.traceparent(task.trace))
	response, err := f.client.Do(request)
	if err != nil {
		return nil, errors.New("fixture MCP unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		return nil, errors.New("fixture MCP refused task")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(data) > 16384 {
		return nil, errors.New("fixture MCP response refused")
	}
	return data, nil
}

func (f *agentFixture) downstream(ctx context.Context, trace string) error {
	// The MCP bearer is deliberately not an argument. This obtains independently
	// authorized actor evidence for a different resource server and audience.
	token, err := f.input(ctx, f.config.ActorCredentials, f.config.ActorClient, f.config.ActorSubject,
		f.config.DownstreamAudience, f.config.ResourceName)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.config.PublicURL+"/downstream", nil)
	if err != nil {
		return errors.New("fixture downstream request refused")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Fixture-Gateway", f.proof)
	request.Header.Set("traceparent", f.audit.traceparent(trace))
	response, err := f.client.Do(request)
	if err != nil {
		return errors.New("fixture downstream unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("fixture downstream refused")
	}
	if !f.audit.record(trace, "downstream", "allow", f.config.PolicyRevision) {
		return errors.New("fixture audit unavailable")
	}
	return nil
}

func readFixtureCredential(path string, limit int) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil || len(value) == 0 || len(value) > limit {
		return "", errors.New("fixture workload credential unavailable")
	}
	return strings.TrimSpace(string(value)), nil
}
func (f *agentFixture) approveTask(ctx context.Context, task *taskAssignment, fields url.Values, actor, subject string) error {
	if f.config.TaskAuthorization == nil {
		return nil
	}
	approval, err := f.registerTask(ctx, task, actor, subject)
	if err != nil {
		return err
	}
	if f.config.QualificationProbe == "invalid-approval" {
		approval = randomReference(32)
	}
	fields.Set("task_context", approval)
	return nil
}
