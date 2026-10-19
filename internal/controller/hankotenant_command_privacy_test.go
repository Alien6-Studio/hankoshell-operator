package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/go-logr/logr/funcr"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestFleetUnapprovedCommandFieldsNeverReachLogs(t *testing.T) {
	f := newFleetUnitFixture(t)
	private := "private-command-person@example.invalid"
	var messages []string
	logger := funcr.New(func(_, args string) { messages = append(messages, args) }, funcr.Options{})
	ctx := log.IntoContext(context.Background(), logger)
	_, err := f.r.executeAgentUpdate(ctx, f.tenant, fleetStatusPatch(f.tenant), nil, &hub.AgentUpdateCommand{Version: private, Digest: private})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(messages, "\n"), private) {
		t.Fatal("unapproved remote command fields leaked before validation")
	}
}
