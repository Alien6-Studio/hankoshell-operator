package observability

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"strings"
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
	"FleetAuthorityChanged":               "Fleet reconciliation refused; inspect condition reason",
	"FleetCacheInvalid":                   "Fleet reconciliation refused; inspect condition reason",
	"FleetCacheTooLarge":                  "Fleet reconciliation refused; inspect condition reason",
	"FleetCacheWriteFailed":               "Fleet reconciliation refused; inspect condition reason",
	"FleetCapabilitiesUnsupported":        "Fleet reconciliation refused; inspect condition reason",
	"FleetCapabilityInventoryUnavailable": "Fleet reconciliation refused; inspect condition reason",
	"FleetCapabilityRefused":              "Fleet reconciliation refused; inspect condition reason",
	"FleetCapabilityUnsupported":          "Fleet reconciliation refused; inspect condition reason",
	"FleetCheckpointInvalid":              "Fleet reconciliation refused; inspect condition reason",
	"FleetClockRegression":                "Fleet reconciliation refused; inspect condition reason",
	"FleetCommandUnapproved":              "Fleet reconciliation refused; inspect condition reason",
	"FleetContentAuthorityInvalid":        "Fleet reconciliation refused; inspect condition reason",
	"FleetContentInvalid":                 "Fleet reconciliation refused; inspect condition reason",
	"FleetDependencyRefused":              "Fleet reconciliation refused; inspect condition reason",
	"FleetEnvelopeInvalid":                "Fleet reconciliation refused; inspect condition reason",
	"FleetExpiryCheckpointFailed":         "Fleet reconciliation refused; inspect condition reason",
	"FleetHubEndpointUnapproved":          "Fleet reconciliation refused; inspect condition reason",
	"FleetHubStatusUnavailable":           "Fleet reconciliation refused; inspect condition reason",
	"FleetIssuerAuthorityMismatch":        "Fleet reconciliation refused; inspect condition reason",
	"FleetKeyExpired":                     "Fleet reconciliation refused; inspect condition reason",
	"FleetKeyUnapproved":                  "Fleet reconciliation refused; inspect condition reason",
	"FleetLegacyDowngrade":                "Fleet reconciliation refused; inspect condition reason",
	"FleetOperatorVersionInvalid":         "Fleet reconciliation refused; inspect condition reason",
	"FleetOperatorVersionUnsupported":     "Fleet reconciliation refused; inspect condition reason",
	"FleetPayloadInvalid":                 "Fleet reconciliation refused; inspect condition reason",
	"FleetPermissionDenied":               "Fleet reconciliation refused; inspect condition reason",
	"FleetPermissionEvidenceExpired":      "Fleet reconciliation refused; inspect condition reason",
	"FleetPlanDowngrade":                  "Fleet reconciliation refused; inspect condition reason",
	"FleetPlanExpired":                    "Fleet reconciliation refused; inspect condition reason",
	"FleetPlanFailed":                     "Fleet reconciliation refused; inspect condition reason",
	"FleetPlanFetchFailed":                "Fleet reconciliation refused; inspect condition reason",
	"FleetPlanNotYetValid":                "Fleet reconciliation refused; inspect condition reason",
	"FleetProviderScopeUnknown":           "Fleet reconciliation refused; inspect condition reason",
	"FleetProviderVersionMismatch":        "Fleet reconciliation refused; inspect condition reason",
	"FleetRollbackReferenceInvalid":       "Fleet reconciliation refused; inspect condition reason",
	"FleetRolloutPaused":                  "Fleet reconciliation refused; inspect condition reason",
	"FleetRolloutPolicyInvalid":           "Fleet reconciliation refused; inspect condition reason",
	"FleetRolloutRefused":                 "Fleet reconciliation refused; inspect condition reason",
	"FleetSequenceConflict":               "Fleet reconciliation refused; inspect condition reason",
	"FleetSignatureInvalid":               "Fleet reconciliation refused; inspect condition reason",
	"FleetSourceInvalid":                  "Fleet reconciliation refused; inspect condition reason",
	"FleetTargetMismatch":                 "Fleet reconciliation refused; inspect condition reason",
	"FleetTrustChanged":                   "Fleet reconciliation refused; inspect condition reason",
	"FleetTrustInvalid":                   "Fleet reconciliation refused; inspect condition reason",
	"FleetTrustUnavailable":               "Fleet reconciliation refused; inspect condition reason",
	"FleetValidityInvalid":                "Fleet reconciliation refused; inspect condition reason",

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

// TenantRefusalReason preserves the bounded Fleet decision used by operators and
// installed qualification. Unknown reasons never become Event text or labels.
func TenantRefusalReason(reason string) string {
	if strings.HasPrefix(reason, "Fleet") && EventReason(reason) == reason {
		return reason
	}
	return "TenantReconcileRefused"
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
