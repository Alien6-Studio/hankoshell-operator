package observability

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
)

// EventMessages is copied for documentation/qualification without exposing the
// authoritative catalog to mutation. Messages never include caller arguments.
func EventMessages() map[string]string {
	result := make(map[string]string, len(eventMessages))
	for reason, message := range eventMessages {
		result[reason] = message
	}
	return result
}

var eventMessages = map[string]string{
	"ClientCreated":                   "Provider client created",
	"ProtectedRealm":                  "Protected realm requires administrator review",
	"ProtectedAuthorityRealm":         "Protected authority realm requires administrator review",
	"RealmDeleted":                    "Provider realm deleted",
	"SessionsRevoked":                 "Provider sessions revoked",
	"ThemeInstalled":                  "Theme installation completed",
	"ThemeBuildSubmitted":             "Theme build submitted",
	"ThemeCleanupSkipped":             "Theme cleanup requires administrator review",
	"ThemeReconcileFailed":            "Theme reconciliation refused; inspect condition reason",
	"ServiceAccountCredentialRotated": "Service-account credential rotation completed",
	"TenantReconcileRefused":          "Tenant reconciliation refused; inspect condition reason",
	"ProjectionCleanupSkipped":        "External projection cleanup requires administrator review",
	"ProtectedControlPlaneClient":     "Protected control-plane client requires administrator review",
	"SecretRotated":                   "Client credential rotation completed",
	"UnclassifiedEvent":               "Unclassified reconciliation event; inspect condition reason",
}

func EventReason(reason string) string {
	if _, ok := eventMessages[reason]; ok {
		return reason
	}
	return "UnclassifiedEvent"
}

type safeRecorder struct{ delegate events.EventRecorder }

// SafeRecorder freezes Event text, reasons and actions at the output boundary.
// InvolvedObject metadata stays standard Kubernetes metadata, never a metric label.
func SafeRecorder(delegate events.EventRecorder) events.EventRecorder {
	return &safeRecorder{delegate: delegate}
}

func (r *safeRecorder) Eventf(regarding, related runtime.Object, eventType, reason, action, _ string, _ ...any) {
	if r.delegate == nil {
		return
	}
	reason = EventReason(reason)
	if eventType != corev1.EventTypeNormal {
		eventType = corev1.EventTypeWarning
	}
	if action != "Finalize" {
		action = "Reconcile"
	}
	Default.Event(reason, eventType)
	r.delegate.Eventf(regarding, related, eventType, reason, action, "%s", eventMessages[reason])
}
