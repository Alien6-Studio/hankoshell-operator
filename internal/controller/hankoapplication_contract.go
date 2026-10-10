package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applicationbinding"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func applicationIntent(spec api.HankoApplicationSpec) applications.Intent {
	i := applications.Intent{RealmRef: spec.RealmRef, ClientID: spec.ClientID, Protocol: spec.Protocol, Pattern: spec.Type, Theme: spec.Theme,
		RedirectURIs: spec.RedirectURIs, PostLogoutURIs: spec.PostLogoutRedirectURIs, RealmRoleScopes: spec.RealmRoleScopes, ScopesManaged: spec.RealmRoleScopes != nil}
	for _, role := range spec.Roles {
		i.Roles = append(i.Roles, applications.Role{Name: role.Name, Description: role.Description})
	}
	for _, claim := range spec.TokenClaims {
		access := boolOrDefault(claim.AddToAccessToken, true)
		id := boolOrDefault(claim.AddToIDToken, claim.Claim != "aud")
		userinfo := boolOrDefault(claim.AddToUserInfo, true)
		if claim.Claim == "aud" {
			userinfo = false
		}
		i.Claims = append(i.Claims, applications.Claim{Name: claim.Name, Claim: claim.Claim, UserAttribute: claim.UserAttribute, Value: claim.Value,
			JSONType: claim.JSONType, RealmRolePrefix: claim.RealmRolePrefix, RealmRoles: claim.RealmRoles, Multivalued: claim.Multivalued,
			IDToken: id, AccessToken: access, UserInfo: userinfo, Introspection: boolOrDefault(claim.AddToIntrospection, access)})
	}
	for _, mapping := range spec.IdentityMappings {
		i.IdentityMappings = append(i.IdentityMappings, applications.IdentityMapping{Name: mapping.Name, Provider: mapping.IdentityProvider, Claim: mapping.Claim,
			MatchValue: mapping.MatchValue, SyncMode: mapping.SyncMode, RealmRole: mapping.Target.RealmRole, ClientRole: mapping.Target.ClientRole, UserAttribute: mapping.Target.UserAttribute})
	}
	for _, projection := range spec.ClientSecretProjections {
		i.Projections = append(i.Projections, applications.Projection{Namespace: projection.Namespace, Name: projection.Name})
	}
	if spec.SecretRotationPolicy != nil {
		i.Rotation = applicationRotationIntent(spec.SecretRotationPolicy)
	}
	if spec.SAML != nil {
		i.SAML = &applications.SAML{ACS: spec.SAML.AssertionConsumerServices, SignedAssertions: boolOrDefault(spec.SAML.RequireSignedAssertions, true), NameIDFormat: spec.SAML.NameIDFormat}
	}
	return i
}
func applicationRotationIntent(policy *api.SecretRotationPolicy) *applications.Rotation {
	result := &applications.Rotation{Enabled: policy.Enabled, IntervalDays: policy.IntervalDays}
	if policy.ForceRotateAt != nil {
		result.ForceRotateAt = policy.ForceRotateAt.UTC().Format(time.RFC3339Nano)
	}
	return result
}
func applicationEvidence(s *api.HankoApplicationStatus) iamEvidence {
	return iamEvidence{&s.ObservedGeneration, &s.EvaluatedGeneration, &s.AppliedGeneration, &s.ObservationGeneration, &s.ContractVersion, &s.BackendKind, &s.IntentHash, &s.EvaluatedPlanHash, &s.AppliedPlanHash, &s.ObservedStateHash, &s.ObservationPlanHash, &s.DriftState, &s.ObservationComplete, &s.CapabilityEvidence}
}
func applicationCapabilityStatus(c applications.Capabilities) api.ApplicationCapabilitySnapshot {
	return api.ApplicationCapabilitySnapshot{OIDC: c.OIDC, PublicClient: c.PublicClient, ConfidentialClient: c.ConfidentialClient, SAML: c.SAML, SAMLACS: c.SAMLACS,
		SAMLAssertionSigning: c.SAMLAssertionSigning, SAMLResponseSigning: c.SAMLResponseSigning, SAMLMetadata: c.SAMLMetadata, ClientRoles: c.ClientRoles, ProtocolMappers: c.ProtocolMappers}
}
func (r *HankoApplicationReconciler) compileApplicationPlan(ctx context.Context, app *api.HankoApplication, kc *keycloak.Client) (applications.Plan, error) {
	reader := &contractReferenceReader{Client: r.Client, Reader: r.OwnershipReader}
	intent := applicationIntent(app.Spec)
	resolved := applications.ResolvedReferences{Realm: app.Spec.RealmRef, Owner: string(app.UID), Attributes: app.Spec.Attributes,
		MigrationUUID: app.Annotations[applications.MigrationUUIDAnnotation], MigrationObservation: iamcontract.Digest(app.Annotations[applications.MigrationObservationAnnotation])}
	var themeVersion string
	// A realm CR is optional for existing-Keycloak application declarations.
	// Both presence and absence are re-evaluated before every mutation batch.
	var realm api.HankoRealm
	err := reader.Get(ctx, client.ObjectKey{Namespace: app.Namespace, Name: app.Spec.RealmRef}, &realm)
	if err != nil && !apierrors.IsNotFound(err) {
		return applications.Plan{}, err
	}
	if err == nil {
		resolved.PublicBase = realm.Spec.FrontendURL
	}
	if app.Spec.Theme != "" {
		var theme api.HankoTheme
		if err := reader.Get(ctx, client.ObjectKey{Namespace: app.Namespace, Name: app.Spec.Theme}, &theme); err != nil && !apierrors.IsNotFound(err) {
			return applications.Plan{}, err
		}
		themeVersion = theme.ResourceVersion
		if effectiveMode(app) == ModeManage && theme.UID != "" && (theme.Status.Phase != "Ready" || theme.Status.JarPath == "" || theme.Status.ObservedGeneration != theme.Generation) {
			return applications.Plan{}, iamcontract.ErrStale
		}
	}
	if effectiveMode(app) == ModeManage {
		if err := r.applicationProjectionReferences(ctx, app, reader); err != nil {
			return applications.Plan{}, err
		}
	}
	if applications.Protocol(app.Spec.Protocol) == "oidc" && effectiveMode(app) == ModeManage {
		policy, err := effectiveSecretRotationPolicy(ctx, reader, app.Namespace, app.Spec.RealmRef, app.Spec.SecretRotationPolicy)
		if err != nil {
			return applications.Plan{}, err
		}
		if policy != nil && app.Spec.Type != "spa" {
			intent.Rotation = applicationRotationIntent(policy)
		}
	}
	roles := map[string]struct{}{}
	for _, role := range app.Spec.Roles {
		roles[role.Name] = struct{}{}
	}
	for _, mapping := range app.Spec.IdentityMappings {
		mapper, err := identityProviderMapperForApplication(app, mapping, roles)
		if err != nil {
			return applications.Plan{}, iamcontract.ErrRejected
		}
		mapper.Config[applications.OwnerAttribute] = string(app.UID)
		resolved.IdentityMappers = append(resolved.IdentityMappers, mapper)
	}
	for _, claim := range app.Spec.TokenClaims {
		mapper, err := protocolMapperForClient(app.Namespace, app.Name, claim)
		if err != nil {
			return applications.Plan{}, iamcontract.ErrRejected
		}
		mapper.Config[applications.OwnerAttribute] = string(app.UID)
		resolved.Mappers = append(resolved.Mappers, mapper)
	}
	pre := executionPreconditions(app, reader.digest(), effectiveMode(app))
	// Approval annotations and installed provider/control-plane identity are
	// execution authority, not portable meaning. No credentials are included.
	authority, _ := json.Marshal(struct {
		Base                                iamcontract.Digest
		MigrationUUID, MigrationObservation string
		ProtectedRealm                      string
		ProtectedClients                    []string
		Endpoint, CredentialClient          string
		ThemeVersion                        string
	}{
		pre.Authority, app.Annotations[applications.MigrationUUIDAnnotation], app.Annotations[applications.MigrationObservationAnnotation], r.ProtectedRealm, r.ProtectedClientIDs, kc.BaseURL(), kc.CredentialClientID(), themeVersion})
	pre.Authority = iamcontract.Hash(iamcontract.Version, "local", "application-authority", authority)
	return applications.Compile(intent, resolved, applications.KeycloakEvidence(), pre)
}
func (r *HankoApplicationReconciler) validateApplicationExecution(ctx context.Context, app *api.HankoApplication, kc *keycloak.Client, p applications.Plan) error {
	reader := client.Reader(r.Client)
	if r.OwnershipReader != nil {
		reader = r.OwnershipReader
	}
	var current api.HankoApplication
	if err := reader.Get(ctx, client.ObjectKeyFromObject(app), &current); err != nil {
		return err
	}
	if !current.DeletionTimestamp.IsZero() {
		return iamcontract.ErrStale
	}
	next, err := r.compileApplicationPlan(ctx, &current, kcForObject(r.Pool, current.Namespace, current.Labels))
	if err != nil {
		return err
	}
	if err := p.Validate(next); err != nil {
		return err
	}
	if reason, conflict, err := r.applicationOwnershipConflict(ctx, &current, kc); err != nil {
		return err
	} else if conflict != "" {
		return fmt.Errorf("local application ownership changed: %s", reason)
	}
	return validateApplicationEffectiveAuthorityRoles(ctx, &current, r.ProtectedRealm, r.ProtectedClientIDs, kc)
}

func (r *HankoApplicationReconciler) validateOwnedApplicationExecution(ctx context.Context, app *api.HankoApplication, kc *keycloak.Client, p applications.Plan) error {
	if err := r.validateApplicationExecution(ctx, app, kc, p); err != nil {
		return err
	}
	state, err := applications.NewKeycloakDriver(kc).CheckOwned(ctx, p)
	if err != nil {
		return err
	}
	if !state.Present || !state.Owned {
		return applications.ErrOwnershipConflict
	}
	if state.Protocol != applications.Protocol(app.Spec.Protocol) {
		return applications.ErrProtocolChange
	}
	return nil
}
func applicationFailureReason(err error) string {
	var runtimeFailure *applicationbinding.Failure
	if errors.As(err, &runtimeFailure) {
		return runtimeFailure.Reason
	}
	switch {
	case errors.Is(err, applications.ErrProtocolChange):
		return "ProtocolChangeRequiresRecreation"
	case errors.Is(err, applications.ErrProtocolMismatch):
		return "ProtocolMismatch"
	case errors.Is(err, applications.ErrOwnershipConflict):
		return "OwnershipApprovalRequired"
	default:
		return iamFailureReason(err, "ApplicationReconcileFailed")
	}
}
func (r *HankoApplicationReconciler) applicationContractError(ctx context.Context, app *api.HankoApplication, patch client.Patch, plan *applications.Plan, state *applications.State, err error) (ctrl.Result, error) {
	markRuntimePending(app, "ApplicationNotReady")
	app.Status.OIDCEndpoints, app.Status.SAMLEndpoints = nil, nil
	if effectiveMode(app) == ModeObserve {
		app.Status.ClientSecret = nil
		app.Status.LastRotated, app.Status.NextRotation = nil, nil
	}
	iamCondition(&app.Status.Conditions, app.Generation, "Operational", metav1.ConditionFalse, "NotEvaluated", "application protocol is not ready for metadata validation")
	e := applicationEvidence(&app.Status)
	e.process(app.Generation, effectiveMode(app) == ModeObserve)
	if plan != nil {
		e.evaluate(app.Generation, plan.Identity())
		app.Status.Capabilities = applicationCapabilityStatus(plan.Evidence().Supported)
	} else {
		e.evaluate(app.Generation, iamcontract.PlanIdentity{Contract: iamcontract.Version, Backend: iamcontract.Keycloak, Intent: applications.IntentIdentity(applicationIntent(app.Spec))})
	}
	if state != nil && plan != nil && iamcontract.ValidDigest(string(state.Observation.StateHash)) {
		e.observe(app.Generation, plan.Identity(), state.Observation)
		app.Status.Protocol = state.Protocol
		app.Status.Findings = findingsStatus(state.Findings)
	}
	reason := applicationFailureReason(err)
	app.Status.Phase = "Error"
	if reason == "OwnershipApprovalRequired" {
		app.Status.Phase = "Conflict"
	}
	app.Status.Findings = findingsStatus(append(stateFindings(state), iamcontract.Finding{Classification: iamcontract.Unsupported, ObjectKind: "application", Code: reason, Message: err.Error(), ReadOnly: effectiveMode(app) == ModeObserve}))
	iamCondition(&app.Status.Conditions, app.Generation, "Synced", metav1.ConditionFalse, reason, err.Error())
	if patchErr := r.Status().Patch(ctx, app, patch); patchErr != nil {
		return ctrl.Result{}, patchErr
	}
	// Stable lifecycle/unsupported conflicts are status, not retrying exceptions.
	if errors.Is(err, applications.ErrOwnershipConflict) || errors.Is(err, applications.ErrProtocolChange) || errors.Is(err, applications.ErrProtocolMismatch) || errors.Is(err, iamcontract.ErrRejected) {
		return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, err
}
func stateFindings(state *applications.State) []iamcontract.Finding {
	if state == nil {
		return nil
	}
	return state.Findings
}

func (r *HankoApplicationReconciler) reconcileApplicationContract(ctx context.Context, app *api.HankoApplication, kc *keycloak.Client, patch client.Patch, observe bool) (ctrl.Result, error) {
	plan, err := r.compileApplicationPlan(ctx, app, kc)
	if err != nil {
		return r.applicationContractError(ctx, app, patch, nil, nil, err)
	}
	e := applicationEvidence(&app.Status)
	e.process(app.Generation, observe)
	e.evaluate(app.Generation, plan.Identity())
	app.Status.Capabilities = applicationCapabilityStatus(plan.Evidence().Supported)
	driver := applications.NewKeycloakDriver(kc)
	var state applications.State
	if observe {
		app.Status.ClientSecret = nil
		app.Status.LastRotated, app.Status.NextRotation = nil, nil
		state, err = driver.Observe(ctx, plan)
	} else {
		if err = r.validateApplicationExecution(ctx, app, kc, plan); err != nil {
			return r.applicationContractError(ctx, app, patch, &plan, nil, err)
		}
		// Independently observe on every attempt. A runtime delivery retry must
		// not repeat provider/client/mapper writes when supported state is current.
		state, err = driver.Observe(ctx, plan)
		if err == nil && !applicationStateCurrent(state, app) {
			state, err = driver.Ensure(ctx, plan)
		}
		if err == nil && state.Created && r.Recorder != nil {
			r.Recorder.Eventf(app, nil, corev1.EventTypeNormal, "ClientCreated", "Reconcile", "%s", "owned application client created")
		}
	}
	if err != nil {
		return r.applicationContractError(ctx, app, patch, &plan, &state, err)
	}
	e.observe(app.Generation, plan.Identity(), state.Observation)
	app.Status.Protocol = state.Protocol
	app.Status.Findings = findingsStatus(state.Findings)
	if !state.Present {
		return r.applicationContractError(ctx, app, patch, &plan, &state, fmt.Errorf("application client not found"))
	}
	if state.Protocol != applications.Protocol(app.Spec.Protocol) {
		return r.applicationContractError(ctx, app, patch, &plan, &state, applications.ErrProtocolMismatch)
	}
	if !observe {
		// Each existing child reconciler retains its local authorization/journal
		// behavior. The adapter independently reads their semantic results back.
		if err = r.validateOwnedApplicationExecution(ctx, app, kc, plan); err != nil {
			return r.applicationContractError(ctx, app, patch, &plan, &state, err)
		}
		if state.Created || !applicationStateCurrent(state, app) {
			if err = r.reconcileApplicationChildren(ctx, app, kc); err != nil {
				return r.applicationContractError(ctx, app, patch, &plan, &state, iamcontract.SafeError(err))
			}
		} else if applicationMapperCleanupPending(app) {
			if err = r.reconcileApplicationMappings(ctx, app, kc); err != nil {
				return r.applicationContractError(ctx, app, patch, &plan, &state, iamcontract.SafeError(err))
			}
		}
		if applications.Protocol(app.Spec.Protocol) == "oidc" {
			if err = r.validateOwnedApplicationExecution(ctx, app, kc, plan); err != nil {
				return r.applicationContractError(ctx, app, patch, &plan, &state, err)
			}
			if state.Created && app.Status.LastRotated == nil && app.Spec.Type != "spa" {
				app.Status.LastRotated = &metav1.Time{Time: time.Now()}
			}
			if err = r.ensureSecret(ctx, app, kc); err != nil {
				return r.applicationContractError(ctx, app, patch, &plan, &state, iamcontract.SafeError(err))
			}
			policy, err := effectiveSecretRotationPolicy(ctx, r.Client, app.Namespace, app.Spec.RealmRef, app.Spec.SecretRotationPolicy)
			if err != nil {
				return r.applicationContractError(ctx, app, patch, &plan, &state, err)
			}
			if app.Spec.Type == "spa" && app.Spec.SecretRotationPolicy == nil {
				policy = nil
			}
			now := metav1.Now()
			if state.Created && app.Status.LastRotated == nil && app.Spec.Type != "spa" {
				setApplicationSecretStatus(app, &now, policy)
			}
			if err = r.maybeRotateApplicationSecret(ctx, app, policy, &now, kc); err != nil {
				return r.applicationContractError(ctx, app, patch, &plan, &state, iamcontract.SafeError(err))
			}
		} else {
			app.Status.ClientSecret = nil
			app.Status.LastRotated, app.Status.NextRotation = nil, nil
		}
		if err = r.validateOwnedApplicationExecution(ctx, app, kc, plan); err != nil {
			return r.applicationContractError(ctx, app, patch, &plan, &state, err)
		}
		state, err = driver.Observe(ctx, plan)
		if err != nil {
			return r.applicationContractError(ctx, app, patch, &plan, nil, err)
		}
		e.observe(app.Generation, plan.Identity(), state.Observation)
		if err = observationError(state.Observation); err != nil {
			return r.applicationContractError(ctx, app, patch, &plan, &state, err)
		}
		if !state.Owned {
			return r.applicationContractError(ctx, app, patch, &plan, &state, applications.ErrOwnershipConflict)
		}
		e.apply(app.Generation, plan.Identity())
	}
	app.Status.Phase = "Ready"
	app.Status.LastReconciled = &metav1.Time{Time: time.Now()}
	reason, message := "Reconciled", "owned application contract proven by provider read-back"
	if observe {
		reason, message = "Observed", "application observed; no provider writes or secret reads"
	}
	iamCondition(&app.Status.Conditions, app.Generation, "Synced", metav1.ConditionTrue, reason, message)
	r.applicationProtocolStatus(ctx, app, driver, plan)
	if observe {
		app.Status.AdoptionCandidate = refreshImportedCandidate(ctx, r.Client, r.OwnershipReader, app)
		markRuntimePending(app, "NotConfigured")
	} else if len(app.Spec.RuntimeBindings) != 0 {
		markRuntimePending(app, "OutputPending")
		app.Status.Phase = "Pending"
	}
	if err := r.Status().Patch(ctx, app, patch); err != nil {
		return ctrl.Result{}, err
	}
	if !observe {
		return r.reconcileRuntimeBindings(ctx, app, kc, plan, driver)
	}
	return ctrl.Result{RequeueAfter: requeueWithJitter()}, nil
}

func applicationStateCurrent(state applications.State, app *api.HankoApplication) bool {
	return state.Present && state.Owned && state.Protocol == applications.Protocol(app.Spec.Protocol) && state.Observation.Complete && !state.Observation.Drifted
}

func (r *HankoApplicationReconciler) reconcileApplicationChildren(ctx context.Context, app *api.HankoApplication, kc *keycloak.Client) error {
	if err := r.reconcileRoles(ctx, app, kc); err != nil {
		return err
	}
	if applications.Protocol(app.Spec.Protocol) != "oidc" {
		return nil
	}
	if err := r.reconcileRealmRoleScopes(ctx, app, kc); err != nil {
		return err
	}
	return r.reconcileApplicationMappings(ctx, app, kc)
}
func (r *HankoApplicationReconciler) applicationProtocolStatus(ctx context.Context, app *api.HankoApplication, driver applications.Driver, plan applications.Plan) {
	metadata, err := driver.Metadata(ctx, plan)
	if applications.Protocol(app.Spec.Protocol) == "oidc" {
		app.Status.SAMLEndpoints = nil
		app.Status.OIDCEndpoints = nil
		if metadata.Issuer != "" {
			app.Status.OIDCEndpoints = &api.OIDCEndpoints{Issuer: metadata.Issuer, Authorization: metadata.Authorization, Token: metadata.Token, JWKS: metadata.JWKS, UserInfo: metadata.UserInfo}
		}
	} else {
		app.Status.OIDCEndpoints = nil
		app.Status.SAMLEndpoints = nil
		if err == nil {
			app.Status.SAMLEndpoints = &api.SAMLEndpoints{Issuer: metadata.Issuer, SSO: metadata.SSO, Metadata: metadata.URL, ResponseBinding: applications.POSTBinding}
		}
	}
	status, reason, message := metav1.ConditionTrue, "Reachable", "bounded protocol metadata matches the configured realm identity"
	if err != nil {
		status, reason, message = metav1.ConditionFalse, "Unreachable", "protocol metadata could not be validated"
	}
	iamCondition(&app.Status.Conditions, app.Generation, "Operational", status, reason, message)
}

// Deletion has independent UID authority and does not require the desired
// protocol to match. This allows reviewed recreation after a refused conversion.
func applicationDeletionPlan(app *api.HankoApplication) (applications.Plan, error) {
	return applications.Compile(applications.Intent{RealmRef: app.Spec.RealmRef, ClientID: app.Spec.ClientID}, applications.ResolvedReferences{Realm: app.Spec.RealmRef, Owner: string(app.UID)}, applications.KeycloakEvidence(), executionPreconditions(app, "", ModeManage))
}

func validateApplicationProtocol(app *api.HankoApplication) error {
	if err := applicationbinding.Validate(app); err != nil {
		return err
	}
	_, err := applications.Compile(applicationIntent(app.Spec), applications.ResolvedReferences{Realm: app.Spec.RealmRef, Owner: string(app.UID), Attributes: app.Spec.Attributes}, applications.KeycloakEvidence(), iamcontract.Preconditions{})
	return err
}

// isSAMLApplication is used only at Kubernetes/secret boundaries, never provider mapping.
func isSAMLApplication(app *api.HankoApplication) bool {
	return strings.EqualFold(app.Spec.Protocol, "saml")
}
