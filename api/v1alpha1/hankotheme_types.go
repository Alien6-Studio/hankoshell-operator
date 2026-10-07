package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ht,categories=hanko
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="BuildJob",type=string,JSONPath=".status.buildJob"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// HankoTheme represents a Keycloakify login theme managed by the operator.
// The operator submits a K8s Job to build the theme JAR and copy it to the Keycloak PVC.
type HankoTheme struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HankoThemeSpec   `json:"spec,omitempty"`
	Status HankoThemeStatus `json:"status,omitempty"`
}

// HankoThemeSpec defines the desired theme configuration.
type HankoThemeSpec struct {
	// RebuildNonce requests a fresh build when its value changes, even if the
	// visual configuration is otherwise identical.
	// +kubebuilder:validation:MaxLength=128
	RebuildNonce string `json:"rebuildNonce,omitempty"`

	// PrimaryColor is the CSS color for the primary UI elements (for example a
	// hex value or oklch()).
	// +kubebuilder:validation:MaxLength=128
	PrimaryColor string `json:"primaryColor,omitempty"`

	// LogoURL is the URL of the logo image shown on the login page.
	// +kubebuilder:validation:MaxLength=2048
	LogoURL string `json:"logoURL,omitempty"`

	// Headline is the text shown above the login form.
	// +kubebuilder:validation:MaxLength=256
	Headline string `json:"headline,omitempty"`

	// Subline is the optional supporting text shown below the headline.
	// +kubebuilder:validation:MaxLength=512
	Subline string `json:"subline,omitempty"`

	// BackgroundColor is the CSS color used for the dark-mode page background.
	// +kubebuilder:validation:MaxLength=128
	BackgroundColor string `json:"backgroundColor,omitempty"`

	// ForegroundColor is the CSS color used for the dark-mode foreground.
	// +kubebuilder:validation:MaxLength=128
	ForegroundColor string `json:"foregroundColor,omitempty"`

	// FontFamily is the CSS font-family applied by the generated theme.
	// +kubebuilder:validation:MaxLength=256
	FontFamily string `json:"fontFamily,omitempty"`

	// BuildImage is the container image used to build the Keycloakify JAR.
	// +kubebuilder:validation:Required
	BuildImage string `json:"buildImage"`

	// KeycloakPVC is the name of the PersistentVolumeClaim where the JAR is placed.
	// +kubebuilder:validation:Required
	KeycloakPVC string `json:"keycloakPVC"`

	// JarName is the filename installed in Keycloak's providers directory. When
	// omitted, the operator derives <metadata.name>-theme.jar.
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._-]+\.jar$`
	JarName string `json:"jarName,omitempty"`

	// ImagePullSecrets are attached to theme build and cleanup Jobs.
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
}

// HankoThemeStatus describes the observed state of the theme build.
type HankoThemeStatus struct {
	// Phase summarises the build state.
	// +kubebuilder:validation:Enum=Pending;Building;Installing;Ready;Error
	Phase string `json:"phase,omitempty"`

	// JarPath is the path inside the PVC where the built JAR was placed.
	JarPath string `json:"jarPath,omitempty"`

	// BuildJob is the name of the most recent K8s Job that built this theme.
	BuildJob string `json:"buildJob,omitempty"`

	// LastBuilt is the timestamp when the theme JAR was last successfully built.
	LastBuilt *metav1.Time `json:"lastBuilt,omitempty"`

	// LastReconciled is the timestamp of the last successful reconciliation.
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// ObservedGeneration is the HankoTheme generation represented by the
	// installed JAR and Ready status.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// InstalledPVC records the claim containing JarPath. It lets cleanup remain
	// correct when spec.keycloakPVC changes after an installation.
	InstalledPVC string `json:"installedPVC,omitempty"`

	// InstalledBuildImage records the previously validated image that can remove
	// the installed artifact even if the desired build image later changes.
	InstalledBuildImage string `json:"installedBuildImage,omitempty"`

	// InstalledImagePullSecrets records the credentials used by the installed
	// build image so finalizer cleanup does not depend on a later spec revision.
	InstalledImagePullSecrets []corev1.LocalObjectReference `json:"installedImagePullSecrets,omitempty"`

	// Conditions holds standard Kubernetes condition objects.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoThemeList contains a list of HankoTheme.
type HankoThemeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoTheme `json:"items"`
}
