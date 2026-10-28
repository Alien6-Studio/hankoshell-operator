package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const taskClaim = "urn:alien6:bounded-delegation:task"
const taskEndpointAudience = "bounded-delegation-task-context"

type taskConfiguration struct {
	AuthorityClient      string `json:"authorityClient"`
	AuthorityCredentials string `json:"authorityCredentials"`
	RecipientCredentials string `json:"recipientCredentials"`
	AudienceID           string `json:"audienceID"`
	Grant                string `json:"grant"`
}

func operationHash() string {
	// This fixture has one fixed operation and no private or agent-selected arguments.
	value := sha256.Sum256([]byte(`{"arguments":{},"name":"read_invoice"}`))
	return hex.EncodeToString(value[:])
}

func (f *agentFixture) taskRequest(ctx context.Context, method, path string, body any, authority bool, status int) ([]byte, error) {
	c := f.config.TaskAuthorization
	client, file := f.resource.config.Audience, c.RecipientCredentials
	if authority {
		client, file = c.AuthorityClient, c.AuthorityCredentials
	}
	fields, err := credentials(file, client)
	if err != nil {
		return nil, err
	}
	fields.Set("grant_type", "client_credentials")
	bearer, err := f.token(ctx, fields, "")
	if err != nil {
		return nil, err
	}
	v := f.resource
	v.config.Audience = taskEndpointAudience
	claims, err := v.claims(bearer)
	if err != nil || claims["azp"] != client || claims["act"] != nil {
		return nil, errors.New("fixture task identity refused")
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, f.resource.config.Issuer+"/bounded-delegation/task-context"+path, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("fixture task request refused")
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(request)
	if err != nil {
		return nil, errors.New("fixture task authority unavailable")
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(result) > 8192 || response.StatusCode != status {
		return nil, errors.New("fixture native task refused")
	}
	return result, nil
}

func (f *agentFixture) registerTask(ctx context.Context, task *taskAssignment, actor, subject string) (string, error) {
	a, err := f.resource.claims(actor)
	if err != nil {
		return "", err
	}
	s, err := f.resource.claims(subject)
	if err != nil {
		return "", err
	}
	c := f.config.TaskAuthorization
	body := map[string]any{"audience": c.AudienceID, "grant": c.Grant, "actorJti": a["jti"], "subjectJti": s["jti"],
		"actorSubject": a["sub"], "subjectSubject": s["sub"], "permissions": map[string][]string{f.resource.config.Resources["/allowed"]: {"read"}},
		"parametersHash": operationHash(), "ttlSeconds": 30}
	data, err := f.taskRequest(ctx, http.MethodPost, "/contexts", body, true, 201)
	if err != nil {
		return "", err
	}
	var created struct {
		Reference string `json:"reference"`
		Approval  string `json:"approval"`
		Expires   int64  `json:"expiresAt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&created) != nil || !policyReference.MatchString(created.Reference) || !policyReference.MatchString(created.Approval) ||
		created.Reference == created.Approval || created.Expires <= time.Now().Unix() || created.Expires > time.Now().Add(30*time.Second).Unix() {
		return "", errors.New("fixture task registration refused")
	}
	f.mu.Lock()
	task.nativeContext = created.Reference
	f.mu.Unlock()
	return created.Approval, nil
}

func (f *agentFixture) checkTask(ctx context.Context, task *taskAssignment, claims jwt.MapClaims) error {
	value, ok := claims[taskClaim].(map[string]any)
	if !ok || len(value) != 4 || value["version"] != float64(1) || value["reference"] != task.nativeContext ||
		value["parametersHash"] != operationHash() || value["policyRevision"] != f.config.PolicyRevision {
		return errors.New("fixture signed task binding refused")
	}
	body := map[string]any{"reference": task.nativeContext, "tokenId": task.jti, "parametersHash": operationHash(),
		"resource": f.resource.config.Resources["/allowed"], "scope": "read"}
	data, err := f.taskRequest(ctx, http.MethodPost, "/check", body, false, 200)
	if err != nil {
		return err
	}
	var result struct {
		Active bool `json:"active"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || !result.Active {
		return errors.New("fixture online task refused")
	}
	return nil
}
