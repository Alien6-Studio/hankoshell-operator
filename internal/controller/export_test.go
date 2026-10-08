package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// SetCondition exposes the unexported setCondition for use in tests.
var SetCondition = setCondition

// OIDCEndpoints exposes the unexported oidcEndpoints for use in tests.
var OIDCEndpoints = oidcEndpoints

// ValidateKeycloakURL exposes URL validation for SSRF regression tests.
var ValidateKeycloakURL = validateKeycloakURL

// RequeueInterval exposes the unexported requeueInterval constant for tests.
var RequeueInterval = requeueInterval

// FinalizerName exposes the unexported finalizerName constant for tests.
const FinalizerName = finalizerName

// RealmFinalizerName and SAFinalizerName expose destructive finalizers for
// observe-mode deletion regression tests.
const (
	RealmFinalizerName = realmFinalizerName
	SAFinalizerName    = saFinalizerName
)

// Mode constants exposed for tests.
const (
	ExportModeManage  = ModeManage
	ExportModeObserve = ModeObserve
	ImportedByLabel   = importedByLabel
)

// RealmClientIndexKey exposes the unexported realmClientIndexKey constant for tests.
const RealmClientIndexKey = realmClientIndexKey

// RealmClientKey exposes the unexported realmClientKey helper for tests.
var RealmClientKey = realmClientKey

// EffectiveMode exposes the unexported effectiveMode helper for tests.
var EffectiveMode = effectiveMode

var (
	_ = metav1.Condition{}
	_ = hankoshv1alpha1.OIDCEndpoints{}
	_ = (*keycloak.Client)(nil)
)
