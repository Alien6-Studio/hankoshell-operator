package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sync"
	"time"
)

// A bounded, allowlisted trace record. There is intentionally no arbitrary
// attribute map, token/hash, software/user identifier, URL, prompt or task text.
// W3C trace context allows a deployment's OpenTelemetry collector to correlate
// these events. Exporter availability never supplies authorization evidence.
type agentAudit struct {
	mu                       sync.Mutex
	writer                   io.Writer
	actor, subject, audience string
	traces                   map[string]traceTail
	export                   func(auditRecord) bool
}

type traceTail struct {
	span    string
	expires time.Time
}
type auditRecord struct {
	Schema   int    `json:"schema"`
	Time     string `json:"time"`
	Trace    string `json:"trace_id"`
	Span     string `json:"span_id"`
	Parent   string `json:"parent_span_id,omitempty"`
	Stage    string `json:"stage"`
	Decision string `json:"decision"`
	Policy   string `json:"policy_revision"`
	Actor    string `json:"actor_ref,omitempty"`
	Subject  string `json:"subject_ref,omitempty"`
	Audience string `json:"audience_ref,omitempty"`
	Coverage string `json:"coverage"`
}

var traceReference = regexp.MustCompile(`^[0-9a-f]{32}$`)
var policyReference = regexp.MustCompile(`^[0-9a-f]{64}$`)

func newAgentAudit() *agentAudit {
	return &agentAudit{writer: os.Stderr, traces: map[string]traceTail{}}
}

func (a *agentAudit) bindings(actor, subject, audience string) {
	key := []byte(randomReference(32))
	correlate := func(value string) string {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(value))
		return hex.EncodeToString(mac.Sum(nil))
	}
	a.actor, a.subject, a.audience = correlate("actor:"+actor), correlate("subject:"+subject), correlate("audience:"+audience)
}

func (a *agentAudit) record(trace, stage, decision, revision string) bool {
	if !traceReference.MatchString(trace) || !policyReference.MatchString(revision) {
		return false
	}
	switch stage {
	case "a2a", "exchange", "mcp", "downstream", "task":
	default:
		return false
	}
	if decision != "allow" && decision != "deny" {
		return false
	}
	a.mu.Lock()
	for key, previous := range a.traces {
		if previous.expires.Before(time.Now()) {
			delete(a.traces, key)
		}
	}
	if len(a.traces) >= 1024 {
		a.mu.Unlock()
		return false
	}
	record := auditRecord{Schema: 1, Time: time.Now().UTC().Format(time.RFC3339Nano), Trace: trace, Span: randomReference(8), Parent: a.traces[trace].span,
		Stage: stage, Decision: decision, Policy: revision, Actor: a.actor, Subject: a.subject, Audience: a.audience, Coverage: "local"}
	a.traces[trace] = traceTail{record.Span, time.Now().Add(5 * time.Minute)}
	a.mu.Unlock()
	complete := true
	if a.export != nil {
		complete = a.export(record)
		record.Coverage = "exported"
		if !complete {
			record.Coverage = "incomplete"
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return json.NewEncoder(a.writer).Encode(record) == nil && complete
}

func (a *agentAudit) traceparent(trace string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	span := a.traces[trace].span
	if span == "" {
		span = randomReference(8)
	}
	return "00-" + trace + "-" + span + "-01"
}
