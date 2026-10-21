package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applicationbinding"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authentik"
	"github.com/Alien6-Studio/hankoshell-operator/internal/httpsecurity"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const providerConnectionLabel = "hanko.sh/provider-connection"
const providerJournalAnnotation = "hanko.sh/experimental-provider-journal"
const providerFinalizer = "hanko.sh/experimental-provider-cleanup"

type providerJournal struct {
	Version       int                `json:"version"`
	Owner         string             `json:"owner"`
	Connection    string             `json:"connection"`
	ConnectionUID string             `json:"connectionUID"`
	Endpoint      iamcontract.Digest `json:"endpoint"`
	Client        iamcontract.Digest `json:"client"`
}
type experimentalApplication struct {
	app        *api.HankoApplication
	connection *corev1.ConfigMap
	plan       applications.Plan
	driver     *authentik.Driver
	journal    providerJournal
	references iamcontract.Digest
}

func (r *HankoApplicationReconciler) experimentalSnapshot(ctx context.Context, key client.ObjectKey) (*experimentalApplication, error) {
	reader := client.Reader(r.Client)
	if r.OwnershipReader != nil {
		reader = r.OwnershipReader
	}
	var app api.HankoApplication
	if err := reader.Get(ctx, key, &app); err != nil {
		return nil, err
	}
	name := app.Labels[providerConnectionLabel]
	if !r.ExperimentalAuthentik || !slices.Contains(r.ExperimentalAuthentikConnections, name) || name == "" || !validLocalResourceName(name) || app.Labels["hanko.sh/tenant"] != "" || app.Spec.RealmRef == r.ProtectedRealm || app.Annotations[applications.MigrationUUIDAnnotation] != "" || app.Annotations[applications.MigrationObservationAnnotation] != "" || len(app.Spec.Attributes) > 0 || len(app.Spec.RuntimeBindings) > 0 || controllerutil.ContainsFinalizer(&app, finalizerName) || app.Status.ClientSecret != nil || len(app.Status.ManagedClientSecretProjections) > 0 || app.Annotations[applicationbinding.JournalAnnotation] != "" {
		return nil, authentik.ErrUnsupported
	}
	realmVersions, err := experimentalRealmVersions(ctx, reader, &app, name)
	if err != nil {
		return nil, err
	}
	var connection corev1.ConfigMap
	if err := reader.Get(ctx, client.ObjectKey{Namespace: app.Namespace, Name: name}, &connection); err != nil {
		return nil, iamcontract.SafeError(err)
	}
	if !connection.DeletionTimestamp.IsZero() || len(connection.Data) != 1 || len(connection.BinaryData) != 0 || len(connection.Data["connection.json"]) > 16384 {
		return nil, authentik.ErrUnsupported
	}
	var config authentik.Connection
	if err := decodeProviderJSON([]byte(connection.Data["connection.json"]), &config); err != nil || config.Validate() != nil {
		return nil, authentik.ErrUnsupported
	}
	intent := applicationIntent(app.Spec)
	refs := applications.ResolvedReferences{Realm: config.Realm, Owner: string(app.UID), PublicBase: config.Endpoint, ConnectionIdentity: config.Identity()}
	if config.Realm != app.Spec.RealmRef || iamcontract.Accept(authentik.Classify(intent, refs)) != nil {
		return nil, authentik.ErrUnsupported
	}
	var token corev1.Secret
	if err := reader.Get(ctx, client.ObjectKey{Namespace: app.Namespace, Name: config.TokenSecret}, &token); err != nil {
		return nil, iamcontract.SafeError(err)
	}
	if !token.DeletionTimestamp.IsZero() || len(token.Data["token"]) == 0 || len(token.Data["token"]) > 8192 {
		return nil, authentik.ErrUnsupported
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	versions := append(realmVersions, string(connection.UID), connection.ResourceVersion, string(token.UID), token.ResourceVersion)
	if config.CASecret != "" {
		var ca corev1.Secret
		if err := reader.Get(ctx, client.ObjectKey{Namespace: app.Namespace, Name: config.CASecret}, &ca); err != nil {
			return nil, iamcontract.SafeError(err)
		}
		if !ca.DeletionTimestamp.IsZero() || len(ca.Data["ca.crt"]) > 262144 {
			return nil, authentik.ErrUnsupported
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(ca.Data["ca.crt"]) {
			return nil, authentik.ErrUnsupported
		}
		versions = append(versions, string(ca.UID), ca.ResourceVersion)
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, authentik.ErrUnsupported
	}
	transport := base.Clone()
	transport.TLSClientConfig = tlsConfig
	httpClient, err := authentik.NewClient(config.Endpoint, string(token.Data["token"]), &http.Client{Transport: transport})
	if err != nil {
		return nil, err
	}
	driver, err := authentik.NewDriver(httpClient, config)
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(versions)
	refHash := iamcontract.Hash(iamcontract.Version, "experimental-provider", "references", data)
	plan, err := applications.CompileForBackend(iamcontract.Authentik, intent, refs, authentik.Evidence(), executionPreconditions(&app, refHash, effectiveMode(&app)))
	if err != nil {
		return nil, err
	}
	journal := providerJournal{Version: 1, Owner: string(app.UID), Connection: name, ConnectionUID: string(connection.UID), Endpoint: iamcontract.Hash(iamcontract.Version, "experimental-provider", "endpoint", []byte(config.Endpoint)), Client: iamcontract.Hash(iamcontract.Version, "experimental-provider", "client", []byte(config.Realm+"\x00"+app.Spec.ClientID))}
	if raw := app.Annotations[providerJournalAnnotation]; raw != "" {
		var existing providerJournal
		if len(raw) > 2048 || decodeProviderJSON([]byte(raw), &existing) != nil || existing != journal {
			return nil, authentik.ErrConflict
		}
	}
	return &experimentalApplication{app: &app, connection: &connection, plan: plan, driver: driver, journal: journal, references: refHash}, nil
}
func validLocalResourceName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, r := range name {
		if r != '.' && r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return name[0] != '.' && name[0] != '-' && name[len(name)-1] != '.' && name[len(name)-1] != '-'
}
func decodeProviderJSON(data []byte, target any) error {
	if httpsecurity.ValidateJSON(data) != nil {
		return authentik.ErrUnsupported
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return authentik.ErrUnsupported
	}
	if decoder.Decode(new(any)) != io.EOF {
		return authentik.ErrUnsupported
	}
	return nil
}
func (r *HankoApplicationReconciler) reconcileExperimentalApplication(ctx context.Context, app *api.HankoApplication) (ctrl.Result, error) {
	key := client.ObjectKeyFromObject(app)
	snapshot, err := r.experimentalSnapshot(ctx, key)
	if err != nil {
		return r.experimentalFailure(ctx, app, err)
	}
	app = snapshot.app
	manage := effectiveMode(app) == ModeManage
	if !app.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(app, providerFinalizer) {
			return ctrl.Result{}, nil
		}
		if !manage || app.Annotations[providerJournalAnnotation] == "" {
			return r.experimentalFailure(ctx, app, authentik.ErrConflict)
		}
		if err := snapshot.driver.DeleteOwned(ctx, snapshot.plan); err != nil {
			return r.experimentalFailure(ctx, app, err)
		}
		patch := client.MergeFrom(app.DeepCopy())
		controllerutil.RemoveFinalizer(app, providerFinalizer)
		delete(app.Annotations, providerJournalAnnotation)
		return ctrl.Result{}, r.Patch(ctx, app, patch)
	}
	if manage && (app.Annotations[providerJournalAnnotation] == "" || !controllerutil.ContainsFinalizer(app, providerFinalizer)) {
		patch := client.MergeFromWithOptions(app.DeepCopy(), client.MergeFromWithOptimisticLock{})
		if app.Annotations == nil {
			app.Annotations = map[string]string{}
		}
		data, _ := json.Marshal(snapshot.journal)
		app.Annotations[providerJournalAnnotation] = string(data)
		controllerutil.AddFinalizer(app, providerFinalizer)
		return ctrl.Result{RequeueAfter: requeueImmediately}, r.Patch(ctx, app, patch)
	}
	if !manage && app.Annotations[providerJournalAnnotation] != "" {
		return r.experimentalFailure(ctx, app, authentik.ErrConflict)
	}
	// Re-read authority, connection and credential identities before mutation.
	current, err := r.experimentalSnapshot(ctx, key)
	if err != nil {
		return r.experimentalFailure(ctx, app, err)
	}
	if current.app.UID != app.UID || current.app.Generation != app.Generation || current.references != snapshot.references || current.plan.Validate(snapshot.plan) != nil || !reflect.DeepEqual(current.app.Labels, app.Labels) || effectiveMode(current.app) != effectiveMode(app) {
		return r.experimentalFailure(ctx, app, iamcontract.ErrStale)
	}
	var state applications.State
	if manage {
		state, err = current.driver.Ensure(ctx, current.plan)
	} else {
		state, err = current.driver.Observe(ctx, current.plan)
	}
	if err != nil {
		return r.experimentalFailure(ctx, app, err)
	}
	after, err := r.experimentalSnapshot(ctx, key)
	if err != nil || after.plan.Validate(current.plan) != nil || after.app.UID != app.UID || after.app.Generation != app.Generation {
		return r.experimentalFailure(ctx, app, iamcontract.ErrStale)
	}
	app = after.app
	evidence := applicationEvidence(&app.Status)
	evidence.process(app.Generation, !manage)
	evidence.evaluate(app.Generation, current.plan.Identity())
	evidence.observe(app.Generation, current.plan.Identity(), state.Observation)
	app.Status.CapabilityEvidence = api.IAMCapabilityEvidence{Source: "experimental-adapter", QualificationWindow: authentik.Version}
	app.Status.Capabilities = applicationCapabilityStatus(authentik.Evidence().Supported)
	app.Status.ClientSecret = nil
	app.Status.SAMLEndpoints = nil
	metadata, err := current.driver.Metadata(ctx, current.plan)
	if err != nil {
		return r.experimentalFailure(ctx, app, err)
	}
	app.Status.OIDCEndpoints = &api.OIDCEndpoints{Issuer: metadata.Issuer, Authorization: metadata.Authorization, Token: metadata.Token, JWKS: metadata.JWKS, UserInfo: metadata.UserInfo}
	app.Status.Phase = "Ready"
	app.Status.Protocol = "oidc"
	app.Status.Findings = nil
	reason := "ExperimentalObserved"
	synced := metav1.ConditionTrue
	if !manage && !state.Present {
		app.Status.Phase = "Pending"
		app.Status.OIDCEndpoints = nil
		reason = "ExperimentalAbsent"
		synced = metav1.ConditionFalse
	}
	if manage {
		if err := observationError(state.Observation); err != nil {
			return r.experimentalFailure(ctx, app, err)
		}
		evidence.apply(app.Generation, current.plan.Identity())
		reason = "ExperimentalApplied"
	}
	iamCondition(&app.Status.Conditions, app.Generation, "Synced", synced, reason, "experimental provider observation completed")
	iamCondition(&app.Status.Conditions, app.Generation, "Operational", metav1.ConditionFalse, "CredentialBindingUnsupported", "experimental provider credential delivery is not qualified")
	// A merge diff against the typed zero-value capability snapshot omits false
	// members when the API has no snapshot yet. They are required booleans in the
	// existing schema. Send the complete status with the fresh resourceVersion;
	// concurrent spec/status changes still produce an optimistic-lock conflict.
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, r.Status().Update(ctx, app)
}
func (r *HankoApplicationReconciler) experimentalFailure(ctx context.Context, app *api.HankoApplication, err error) (ctrl.Result, error) {
	patch := client.MergeFromWithOptions(app.DeepCopy(), client.MergeFromWithOptimisticLock{})
	app.Status.Phase = "Error"
	app.Status.BackendKind = string(iamcontract.Authentik)
	app.Status.ObservedGeneration = app.Generation
	app.Status.ObservationComplete = false
	app.Status.DriftState = "Unknown"
	app.Status.AppliedGeneration = 0
	app.Status.AppliedPlanHash = ""
	app.Status.OIDCEndpoints = nil
	app.Status.SAMLEndpoints = nil
	reason := "ExperimentalProviderUnavailable"
	if errors.Is(err, authentik.ErrUnsupported) || errors.Is(err, iamcontract.ErrRejected) {
		reason = "ExperimentalUnsupported"
	}
	if errors.Is(err, authentik.ErrConflict) {
		reason = "ExperimentalOwnershipConflict"
	}
	if !r.ExperimentalAuthentik {
		reason = "ExperimentalProviderDisabled"
	}
	app.Status.Findings = []api.AuthorizationFinding{{Classification: "unsupported", ObjectKind: "application", Code: reason, Message: "experimental provider execution is unavailable or refused"}}
	iamCondition(&app.Status.Conditions, app.Generation, "Synced", metav1.ConditionFalse, reason, "experimental provider execution is unavailable or refused")
	iamCondition(&app.Status.Conditions, app.Generation, "Operational", metav1.ConditionFalse, reason, "experimental provider execution is unavailable or refused")
	return ctrl.Result{RequeueAfter: requeueOnError}, r.Status().Patch(ctx, app, patch)
}

// Unsupported provider-labelled domains never fall through to the default
// Keycloak connection, including Observe and deletion paths.
func rejectExperimentalResource(ctx context.Context, kube client.Client, obj client.Object) (ctrl.Result, error) {
	before, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return ctrl.Result{}, authentik.ErrUnsupported
	}
	var phase *string
	var generation *int64
	var conditions *[]metav1.Condition
	switch value := obj.(type) {
	case *api.HankoRealm:
		phase, generation, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
	case *api.HankoRole:
		phase, generation, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
		value.Status.ObservationComplete = false
		value.Status.AppliedGeneration = 0
		value.Status.AppliedPlanHash = ""
	case *api.HankoResourceServer:
		phase, generation, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
		value.Status.ObservationComplete = false
		value.Status.AppliedGeneration = 0
		value.Status.AppliedPlanHash = ""
	case *api.HankoOrganization:
		phase, generation, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
	case *api.HankoServiceAccount:
		phase, generation, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
	case *api.HankoIAMProfile:
		phase, generation, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
		value.Status.PolicyHash = ""
	case *api.HankoWorkloadTrust:
		phase, generation, conditions = &value.Status.Phase, &value.Status.ObservedGeneration, &value.Status.Conditions
	default:
		return ctrl.Result{}, authentik.ErrUnsupported
	}
	*phase = "Error"
	*generation = obj.GetGeneration()
	iamCondition(conditions, obj.GetGeneration(), "Synced", metav1.ConditionFalse, "ExperimentalUnsupported", "domain is outside the experimental provider window; no provider mutation is permitted")
	return ctrl.Result{RequeueAfter: requeueOnError}, kube.Status().Patch(ctx, obj, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
}

// A provider switch must never silently drop inherited realm policy or native
// configuration. Presence/absence and selected realm versions are rechecked by
// the same pre/post-mutation snapshots as credentials and connection authority.
func experimentalRealmVersions(ctx context.Context, reader client.Reader, app *api.HankoApplication, connection string) ([]string, error) {
	var realm api.HankoRealm
	err := reader.Get(ctx, client.ObjectKey{Namespace: app.Namespace, Name: app.Spec.RealmRef}, &realm)
	if apierrors.IsNotFound(err) {
		return []string{"realm-absent"}, nil
	}
	if err != nil {
		return nil, iamcontract.SafeError(err)
	}
	_, tenant := realm.Labels["hanko.sh/tenant"]
	spec := realm.Spec
	spec.DisplayName = ""
	if !realm.DeletionTimestamp.IsZero() || realm.Labels[providerConnectionLabel] != connection || tenant || !reflect.DeepEqual(spec, api.HankoRealmSpec{}) {
		return nil, authentik.ErrUnsupported
	}
	return []string{string(realm.UID), realm.ResourceVersion}, nil
}
