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
	// ProjectGzip is a base64-encoded gzip snapshot of a declarative Studio project.
	// It is mounted read-only for the approved builder, never executed as source code.
	// +kubebuilder:validation:MaxLength=900000
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9+/]+={0,2}$`
	ProjectGzip string `json:"projectGzip,omitempty"`

	// ProjectSHA256 identifies the uncompressed JSON bytes in ProjectGzip.
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	ProjectSHA256 string `json:"projectSHA256,omitempty"`

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

	// BuildImage contains either the approved builder or a precompiled theme
	// artifact. Artifact mode does not execute the image entrypoint or build tools.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[^\x00-\x20\x7F]+$`
	BuildImage string `json:"buildImage"`

	// ArtifactSHA256 selects precompiled installation from /theme/theme.jar in
	// BuildImage. The operator verifies these bytes before an atomic PVC write.
	// Omit it only for explicit local legacy builds. Visual settings are runtime
	// profile data and cannot be combined with artifact installation.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	// +kubebuilder:validation:MaxLength=64
	ArtifactSHA256 string `json:"artifactSHA256,omitempty"`

	// KeycloakPVC is the name of the PersistentVolumeClaim where the JAR is placed.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	KeycloakPVC string `json:"keycloakPVC"`

	// JarName is the filename installed in Keycloak's providers directory. When
	// omitted, the operator derives <metadata.name>-theme.jar.
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._-]+\.jar$`
	// +kubebuilder:validation:MaxLength=255
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
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// HankoThemeList contains a list of HankoTheme.
type HankoThemeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HankoTheme `json:"items"`
}
