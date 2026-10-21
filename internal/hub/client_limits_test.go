package hub

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type measuredHubBody struct {
	io.Reader
	read   int
	closed bool
}

func (b *measuredHubBody) Read(buffer []byte) (int, error) {
	n, err := b.Reader.Read(buffer)
	b.read += n
	return n, err
}

func (b *measuredHubBody) Close() error {
	b.closed = true
	return nil
}

func measuredHubClient(status int, body *measuredHubBody) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status, Body: body, ContentLength: -1,
			Header: http.Header{"X-Hanko-Mesh-Policy-Mode": []string{"audit-only"}},
		}, nil
	})}
}

func TestHubResponseBudgetsBoundReadsAndCloseBodies(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		status int
		limit  int
		call   func(*http.Client) error
	}{
		{"enrollment", http.StatusCreated, maxHubControlResponseBytes, func(client *http.Client) error {
			_, err := enrollWithClient(context.Background(), "https://hub.invalid", "synthetic", EnrollmentIdentity{}, client)
			return err
		}},
		{"rotation", http.StatusCreated, maxHubControlResponseBytes, func(client *http.Client) error {
			_, err := NewWithHTTPClient("https://hub.invalid", "tenant", "synthetic", client).PrepareRotation(context.Background(), "rotation")
			return err
		}},
		{"bundle", http.StatusOK, maxBundleEnvelopeBytes, func(client *http.Client) error {
			_, err := NewWithHTTPClient("https://hub.invalid", "tenant", "synthetic", client).FetchBundle(context.Background())
			return err
		}},
		{"mesh policy", http.StatusOK, maxMeshPolicyEnvelopeBytes, func(client *http.Client) error {
			_, err := NewWithHTTPClient("https://hub.invalid", "tenant", "synthetic", client).FetchMeshPolicy(context.Background())
			return err
		}},
		{"heartbeat", http.StatusOK, maxHubControlResponseBytes, func(client *http.Client) error {
			_, err := NewWithHTTPClient("https://hub.invalid", "tenant", "synthetic", client).ReportStatus(context.Background(), OperatorStatus{})
			return err
		}},
		{"rotation confirmation", http.StatusBadGateway, maxHubErrorResponseBytes, func(client *http.Client) error {
			return NewWithHTTPClient("https://hub.invalid", "tenant", "synthetic", client).ConfirmRotation(context.Background())
		}},
		{"decommission confirmation", http.StatusBadGateway, maxHubErrorResponseBytes, func(client *http.Client) error {
			return NewWithHTTPClient("https://hub.invalid", "tenant", "synthetic", client).ConfirmDecommission(context.Background(), nil)
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			for _, status := range []int{scenario.status, http.StatusBadGateway} {
				limit := scenario.limit
				if status >= http.StatusBadRequest {
					limit = maxHubErrorResponseBytes
				}
				body := &measuredHubBody{Reader: strings.NewReader(strings.Repeat("x", limit*2))}
				err := scenario.call(measuredHubClient(status, body))
				if err == nil || !strings.Contains(err.Error(), "exceeds") {
					t.Fatalf("HTTP %d accepted an oversized response: %v", status, err)
				}
				if body.read > limit+1 || !body.closed {
					t.Fatalf("HTTP %d read %d bytes, budget %d; closed=%v", status, body.read, limit+1, body.closed)
				}
			}
		})
	}
}

func TestHubReadFailureCannotAcceptValidJSONPrefix(t *testing.T) {
	payload := `{"bundle":{"version":"fixture","tenantID":"tenant"},"signature":"fixture"}`
	body := &measuredHubBody{Reader: io.MultiReader(strings.NewReader(payload), failingReader{})}
	client := NewWithHTTPClient("https://hub.invalid", "tenant", "synthetic", measuredHubClient(http.StatusOK, body))
	if bundle, err := client.FetchBundle(context.Background()); bundle != nil || err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("valid JSON prefix from a broken stream was accepted: %v, %v", bundle, err)
	}
	if !body.closed {
		t.Fatal("broken response was not closed")
	}
}

func TestHubBundleAtExactBudgetIsAccepted(t *testing.T) {
	payload := `{"bundle":{"version":"fixture","tenantID":"tenant"},"signature":"fixture"}`
	body := &measuredHubBody{Reader: strings.NewReader(payload + strings.Repeat(" ", maxBundleEnvelopeBytes-len(payload)))}
	client := NewWithHTTPClient("https://hub.invalid", "tenant", "synthetic", measuredHubClient(http.StatusOK, body))
	if bundle, err := client.FetchBundle(context.Background()); err != nil || bundle.Bundle.Version != "fixture" {
		t.Fatalf("response at the exact budget was rejected: %v", err)
	}
}

func TestHubPartialAcknowledgementCannotDeliverCommands(t *testing.T) {
	payload := `{"ok":true,"agentUpdate":{"version":"fixture","digest":"fixture"},"decommission":{"requestedAt":"invalid-date"}}`
	client := NewWithHTTPClient("https://hub.invalid", "tenant", "synthetic", responseClient(http.StatusOK, strings.NewReader(payload), nil))
	ack, err := client.ReportStatus(context.Background(), OperatorStatus{})
	if err != nil || ack == nil || ack.AgentUpdate != nil || ack.Decommission != nil {
		t.Fatalf("malformed acknowledgement delivered a partially decoded command: %+v, %v", ack, err)
	}
}
