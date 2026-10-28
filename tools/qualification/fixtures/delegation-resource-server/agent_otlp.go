package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type otlpAttribute struct {
	Key   string `json:"key"`
	Value struct {
		String string `json:"stringValue"`
	} `json:"value"`
}
type otlpSpan struct {
	Trace      string          `json:"traceId"`
	Span       string          `json:"spanId"`
	Parent     string          `json:"parentSpanId,omitempty"`
	Name       string          `json:"name"`
	Kind       int             `json:"kind"`
	Start      string          `json:"startTimeUnixNano"`
	End        string          `json:"endTimeUnixNano"`
	Attributes []otlpAttribute `json:"attributes"`
}
type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type otlpResource struct {
	Attributes []otlpAttribute `json:"attributes"`
}
type otlpScopeSpans struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}
type otlpResourceSpans struct {
	Resource otlpResource     `json:"resource"`
	Scopes   []otlpScopeSpans `json:"scopeSpans"`
}
type otlpRequest struct {
	Resources []otlpResourceSpans `json:"resourceSpans"`
}

func attribute(key, value string) otlpAttribute {
	var a otlpAttribute
	a.Key = key
	a.Value.String = value
	return a
}

// Decision events become zero-duration OTLP spans, not invented request latency.
// This protocol sink is a disposable fixture, not a production collector.
func (f *agentFixture) exportTrace(record auditRecord) bool {
	now, err := time.Parse(time.RFC3339Nano, record.Time)
	if err != nil {
		return false
	}
	nanos := strconv.FormatInt(now.UnixNano(), 10)
	span := otlpSpan{Trace: record.Trace, Span: record.Span, Parent: record.Parent, Name: "hanko.authority." + record.Stage, Kind: 1, Start: nanos, End: nanos,
		Attributes: []otlpAttribute{attribute("decision", record.Decision), attribute("policy_revision", record.Policy), attribute("actor_ref", record.Actor), attribute("subject_ref", record.Subject), attribute("audience_ref", record.Audience)}}
	document := otlpRequest{Resources: []otlpResourceSpans{{Resource: otlpResource{Attributes: []otlpAttribute{attribute("service.name", "bounded-authority-fixture")}},
		Scopes: []otlpScopeSpans{{Scope: otlpScope{Name: "hanko.qualification", Version: "1.1.0"}, Spans: []otlpSpan{span}}}}}}
	data, err := json.Marshal(document)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.config.PublicURL+"/v1/traces", bytes.NewReader(data))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Fixture-Gateway", f.proof)
	response, err := f.client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(body) > 8192 || response.StatusCode != 200 {
		return false
	}
	var result struct {
		Partial *struct {
			Rejected json.RawMessage `json:"rejectedSpans"`
		} `json:"partialSuccess"`
	}
	return json.Unmarshal(body, &result) == nil && result.Partial == nil
}

func (f *agentFixture) collectTrace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Fixture-Gateway")), []byte(f.proof)) != 1 {
		writeJSON(w, 403, map[string]string{"error": "collector_refused"})
		return
	}
	if f.config.QualificationProbe == "collector-outage" {
		writeJSON(w, 503, map[string]string{"error": "collector_unavailable"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(body) > 16384 {
		writeJSON(w, 413, map[string]string{"error": "collector_limit"})
		return
	}
	var document otlpRequest
	// OTLP JSON receivers ignore unknown protobuf fields for forward compatibility.
	if json.Unmarshal(body, &document) != nil || len(document.Resources) != 1 || len(document.Resources[0].Scopes) != 1 || len(document.Resources[0].Scopes[0].Spans) != 1 {
		writeJSON(w, 400, map[string]string{"error": "collector_document_refused"})
		return
	}
	span := document.Resources[0].Scopes[0].Spans[0]
	if !validOTLPSpan(span) {
		writeJSON(w, 400, map[string]string{"error": "collector_span_refused"})
		return
	}
	if !validOTLPAttributes(span.Attributes) {
		writeJSON(w, 400, map[string]string{"error": "collector_attribute_refused"})
		return
	}
	writeJSON(w, 200, map[string]any{})
}

func validOTLPAttributes(attributes []otlpAttribute) bool {
	// No arbitrary attribute is retained, logged or exported by this fixture sink.
	for _, a := range attributes {
		valid := false
		switch a.Key {
		case "decision":
			valid = a.Value.String == "allow" || a.Value.String == "deny"
		case "policy_revision", "actor_ref", "subject_ref", "audience_ref":
			valid = policyReference.MatchString(a.Value.String)
		}
		if !valid {
			return false
		}
	}
	return true
}

func validOTLPSpan(span otlpSpan) bool {
	return traceReference.MatchString(span.Trace) && len(span.Span) == 16 && strings.HasPrefix(span.Name, "hanko.authority.") && len(span.Attributes) == 5
}
