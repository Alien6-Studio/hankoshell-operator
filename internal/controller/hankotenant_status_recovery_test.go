package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConvergedHeartbeatRecoversWithoutDiscardingCommands(t *testing.T) {
	for _, tc := range []struct {
		name         string
		detail       string
		first        hub.StatusAck
		second       hub.StatusAck
		failAt       int
		wantReports  int
		wantDegraded bool
	}{
		{name: "resolved bundle conflict", detail: "BundleObjectConflict", wantReports: 2},
		{name: "resolved provider error", detail: "KeycloakSecretReadFailed", wantReports: 2},
		{name: "pending update", detail: "AgentUpdateFailed", first: hub.StatusAck{AgentUpdate: &hub.AgentUpdateCommand{Version: "next"}}, wantReports: 1, wantDegraded: true},
		{name: "pending decommission", detail: "DecommissionBlocked", first: hub.StatusAck{Decommission: &hub.DecommissionCommand{}}, wantReports: 1, wantDegraded: true},
		{name: "partial plan", detail: "FleetPlanPartial", wantReports: 1, wantDegraded: true},
		{name: "initial report fails", detail: "BundleObjectConflict", failAt: 1, wantReports: 1, wantDegraded: true},
		{name: "recovery report fails", detail: "BundleObjectConflict", failAt: 2, wantReports: 2, wantDegraded: true},
		{name: "command arrives during recovery", detail: "BundleObjectConflict", second: hub.StatusAck{AgentUpdate: &hub.AgentUpdateCommand{Version: "next"}}, wantReports: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reports []hub.OperatorStatus
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var report hub.OperatorStatus
				if err := json.NewDecoder(req.Body).Decode(&report); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				reports = append(reports, report)
				if len(reports) == tc.failAt {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				ack := tc.first
				if len(reports) == 2 {
					ack = tc.second
				}
				_ = json.NewEncoder(w).Encode(ack)
			}))
			defer server.Close()
			tenant := &api.HankoTenant{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Namespace: "apps"}}
			r := &HankoTenantReconciler{}
			r.rememberDegraded(tenant, tc.detail)
			status := hub.OperatorStatus{Phase: "Error", Health: "degraded", Detail: tc.detail, BundleVersion: "verified-bundle"}
			ack, err := r.reportConvergedStatus(context.Background(), hub.New(server.URL, "tenant-id", "fixture"), tenant, status)
			if (err != nil) != (tc.failAt != 0) {
				t.Fatalf("report error = %v", err)
			}
			if len(reports) != tc.wantReports {
				t.Fatalf("got %d reports, want %d", len(reports), tc.wantReports)
			}
			if _, degraded := r.degradedReason(tenant); degraded != tc.wantDegraded {
				t.Fatalf("sticky degradation = %t, want %t", degraded, tc.wantDegraded)
			}
			if len(reports) == 2 && (reports[1].Phase != "Synced" || reports[1].Health != "healthy" || reports[1].Detail != "" || reports[1].BundleVersion != status.BundleVersion) {
				t.Fatalf("invalid recovered snapshot: %+v", reports[1])
			}
			if tc.second.AgentUpdate != nil && (ack == nil || ack.AgentUpdate == nil || ack.AgentUpdate.Version != tc.second.AgentUpdate.Version) {
				t.Fatal("command received during recovery was lost")
			}
			if tc.first.Decommission != nil && (ack == nil || ack.Decommission == nil) {
				t.Fatal("decommission acknowledgement was lost")
			}
			if tc.first.AgentUpdate != nil && (ack == nil || ack.AgentUpdate == nil) {
				t.Fatal("update acknowledgement was lost")
			}
		})
	}
}
