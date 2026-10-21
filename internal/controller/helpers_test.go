package controller_test

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestSetCondition_AddsNew(t *testing.T) {
	var conditions []metav1.Condition

	controller.SetCondition(&conditions, "Ready", metav1.ConditionTrue, "AllGood", "everything is fine")

	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conditions))
	}
	c := conditions[0]
	if c.Type != "Ready" {
		t.Errorf("Type: got %q, want %q", c.Type, "Ready")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("Status: got %q, want True", c.Status)
	}
	if c.Reason != "AllGood" {
		t.Errorf("Reason: got %q, want %q", c.Reason, "AllGood")
	}
	if c.Message != "everything is fine" {
		t.Errorf("Message: got %q", c.Message)
	}
	if c.LastTransitionTime.IsZero() {
		t.Error("LastTransitionTime must not be zero for a new condition")
	}
}

func TestSetCondition_SameStatus_NoTimeChange(t *testing.T) {
	var conditions []metav1.Condition
	controller.SetCondition(&conditions, "Ready", metav1.ConditionTrue, "R1", "msg1")

	original := conditions[0].LastTransitionTime

	// Sleep a tiny bit so that a new metav1.Now() would differ.
	time.Sleep(5 * time.Millisecond)

	controller.SetCondition(&conditions, "Ready", metav1.ConditionTrue, "R2", "msg2")

	if conditions[0].LastTransitionTime != original {
		t.Error("LastTransitionTime must NOT change when status is the same")
	}
	// But reason and message must be updated.
	if conditions[0].Reason != "R2" {
		t.Errorf("Reason: got %q, want %q", conditions[0].Reason, "R2")
	}
	if conditions[0].Message != "msg2" {
		t.Errorf("Message: got %q, want %q", conditions[0].Message, "msg2")
	}
}

func TestSetCondition_DifferentStatus_TimeChanges(t *testing.T) {
	var conditions []metav1.Condition
	controller.SetCondition(&conditions, "Ready", metav1.ConditionTrue, "R1", "msg1")

	original := conditions[0].LastTransitionTime

	time.Sleep(5 * time.Millisecond)

	controller.SetCondition(&conditions, "Ready", metav1.ConditionFalse, "R2", "msg2")

	if conditions[0].LastTransitionTime == original {
		t.Error("LastTransitionTime MUST change when status changes")
	}
	if conditions[0].Status != metav1.ConditionFalse {
		t.Errorf("Status: got %q, want False", conditions[0].Status)
	}
}

func TestSetCondition_UpdateReasonMessage_NoTimeChange(t *testing.T) {
	var conditions []metav1.Condition
	controller.SetCondition(&conditions, "Synced", metav1.ConditionFalse, "OldReason", "old msg")

	original := conditions[0].LastTransitionTime

	time.Sleep(5 * time.Millisecond)

	// Same type, same status — only reason+message change.
	controller.SetCondition(&conditions, "Synced", metav1.ConditionFalse, "NewReason", "new msg")

	if conditions[0].LastTransitionTime != original {
		t.Error("LastTransitionTime must NOT change when only reason/message are updated")
	}
	if conditions[0].Reason != "NewReason" {
		t.Errorf("Reason: got %q, want NewReason", conditions[0].Reason)
	}
}

func TestOIDCEndpoints(t *testing.T) {
	kc := keycloak.New("https://auth.example.com", "id", "secret")
	ep := controller.OIDCEndpoints(kc, "test")

	if ep == nil {
		t.Fatal("OIDCEndpoints returned nil")
	}

	tests := []struct {
		field string
		got   string
		want  string
	}{
		{"Issuer", ep.Issuer, "https://auth.example.com/realms/test"},
		{"Authorization", ep.Authorization, "https://auth.example.com/realms/test/protocol/openid-connect/auth"},
		{"Token", ep.Token, "https://auth.example.com/realms/test/protocol/openid-connect/token"},
		{"JWKS", ep.JWKS, "https://auth.example.com/realms/test/protocol/openid-connect/certs"},
		{"UserInfo", ep.UserInfo, "https://auth.example.com/realms/test/protocol/openid-connect/userinfo"},
	}

	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.field, tc.got, tc.want)
		}
	}
}

func TestValidateKeycloakURLBlocksMetadataEndpoints(t *testing.T) {
	blocked := []string{
		"http://169.254.169.254/latest/meta-data",
		"https://[fd00:ec2::254]/latest/meta-data",
		"https://100.100.100.200/latest/meta-data",
	}
	for _, rawURL := range blocked {
		t.Run(rawURL, func(t *testing.T) {
			if err := controller.ValidateKeycloakURL(rawURL); err == nil {
				t.Fatalf("expected metadata endpoint %q to be rejected", rawURL)
			}
		})
	}
}

func TestValidateKeycloakURLAcceptsSupportedEndpoints(t *testing.T) {
	for _, rawURL := range []string{"https://keycloak.example.com", "http://keycloak.svc.cluster.local:8080"} {
		t.Run(rawURL, func(t *testing.T) {
			if err := controller.ValidateKeycloakURL(rawURL); err != nil {
				t.Fatalf("expected %q to be accepted: %v", rawURL, err)
			}
		})
	}
}
