package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

// keycloakInternalClients holds the built-in Keycloak clients that must never
// be imported as HankoApplication or HankoServiceAccount objects.
var keycloakInternalClients = map[string]bool{
	"account":                true,
	"account-console":        true,
	"admin-cli":              true,
	"broker":                 true,
	"realm-management":       true,
	"security-admin-console": true,
}

type importedRealmIdentityProvider struct {
	provider keycloak.IdentityProvider
	mappers  []keycloak.IdentityProviderMapper
}

// HankoImportReconciler reconciles HankoImport objects (one-shot operation).
//
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoimports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoimports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hanko.sh,resources=hankorealms,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoapplications,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=hanko.sh,resources=hankoserviceaccounts,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=hanko.sh,resources=hankokeycloakinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
type HankoImportReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	ProtectedClientIDs []string
	ProtectedRealm     string
	// Pool is the operator's shared Keycloak client pool. When non-nil the import
	// uses the pool's default client (same credentials as all other reconcilers)
	// instead of building a new client from the HankoKeycloakInstance adminRef.
	// This guarantees consistent cross-realm access without extra permission grants.
	Pool         *keycloak.Pool
	RequireHTTPS bool
}

type importedRealmData struct {
	realm             keycloak.Realm
	clients           []keycloak.App
	accounts          []keycloak.App
	identityProviders []importedRealmIdentityProvider
}

type importDiscoveryError struct {
	reason  string
	message string
	cause   error
}

func (e *importDiscoveryError) Error() string {
	return e.cause.Error()
}

func (r *HankoImportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var operation hankoshv1alpha1.HankoImport
	if err := r.Get(ctx, req.NamespacedName, &operation); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if operation.Status.Phase == "Done" || operation.Status.Phase == "Failed" {
		return ctrl.Result{}, nil
	}

	patch := client.MergeFrom(operation.DeepCopy())
	operation.Status.Phase = "Scanning"
	if err := r.Status().Patch(ctx, &operation, patch); err != nil {
		log.FromContext(ctx).Error(err, "patch status to Scanning")
	}
	patch = client.MergeFrom(operation.DeepCopy())

	kc, handled := r.importKeycloakClient(ctx, &operation, patch)
	if handled {
		return ctrl.Result{}, nil
	}
	discovered, result, err := r.discoverImport(ctx, &operation, kc, patch)
	if err != nil || discovered == nil {
		return result, err
	}
	if operation.Spec.DryRun {
		return r.completeImportDryRun(ctx, &operation, discovered, patch)
	}

	operation.Status.Phase = "Applying"
	if err := r.Status().Patch(ctx, &operation, patch); err != nil {
		log.FromContext(ctx).Error(err, "patch status to Applying")
	}
	patch = client.MergeFrom(operation.DeepCopy())
	applyErrors := r.applyImport(ctx, &operation, discovered)
	return r.completeImport(ctx, &operation, applyErrors, patch)
}

func (r *HankoImportReconciler) failImport(ctx context.Context, operation *hankoshv1alpha1.HankoImport, patch client.Patch, reason, message, logMessage string) {
	operation.Status.Phase = "Failed"
	setCondition(&operation.Status.Conditions, "ImportReady", metav1.ConditionFalse, reason, message)
	if err := r.Status().Patch(ctx, operation, patch); err != nil {
		log.FromContext(ctx).Error(err, logMessage)
	}
}

func (r *HankoImportReconciler) importKeycloakClient(ctx context.Context, operation *hankoshv1alpha1.HankoImport, patch client.Patch) (*keycloak.Client, bool) {
	if r.Pool != nil {
		return r.Pool.Get(operation.Namespace + "/"), false
	}
	var instance hankoshv1alpha1.HankoKeycloakInstance
	err := r.Get(ctx, types.NamespacedName{Name: operation.Spec.SourceRef, Namespace: operation.Namespace}, &instance)
	if err != nil {
		reason := "SourceError"
		message := fmt.Sprintf("get HankoKeycloakInstance %q: %v", operation.Spec.SourceRef, err)
		if errors.IsNotFound(err) {
			reason = "SourceNotFound"
			message = fmt.Sprintf("HankoKeycloakInstance %q not found in namespace %q", operation.Spec.SourceRef, operation.Namespace)
		}
		r.failImport(ctx, operation, patch, reason, message, "patch status after source not found")
		return nil, true
	}
	kc, err := buildKCClientForInstance(ctx, r.Client, &instance, r.RequireHTTPS)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to build Keycloak client from instance")
		r.failImport(ctx, operation, patch, "KCClientError", err.Error(), "patch status after KC client error")
		return nil, true
	}
	return kc, false
}

func (r *HankoImportReconciler) discoverImport(ctx context.Context, operation *hankoshv1alpha1.HankoImport, kc *keycloak.Client, patch client.Patch) ([]importedRealmData, ctrl.Result, error) {
	realms, err := kc.ListRealms(ctx)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to list realms")
		r.failImport(ctx, operation, patch, "ListRealmsError", err.Error(), "patch status after list realms error")
		return nil, ctrl.Result{}, nil
	}
	selected := selectImportRealms(realms, operation.Spec.Realms)
	includeIdentityProviders := operation.Spec.IncludeIdentityProviders == nil || *operation.Spec.IncludeIdentityProviders
	discovered := make([]importedRealmData, 0, len(selected))
	for _, realm := range selected {
		data, discoverErr := discoverImportedRealm(ctx, kc, realm, includeIdentityProviders)
		if discoverErr != nil {
			log.FromContext(ctx).Error(discoverErr.cause, "failed to discover realm", "realm", realm.URLName())
			r.failImport(ctx, operation, patch, discoverErr.reason, discoverErr.message, "patch status after realm discovery error")
			return nil, ctrl.Result{RequeueAfter: requeueOnError}, discoverErr.cause
		}
		discovered = append(discovered, data)
	}
	operation.Status.Discovered = importDiscoveryCounts(discovered)
	return discovered, ctrl.Result{}, nil
}

func selectImportRealms(realms []keycloak.Realm, requested []string) []keycloak.Realm {
	if len(requested) == 0 {
		return realms
	}
	filter := make(map[string]bool, len(requested))
	for _, name := range requested {
		filter[name] = true
	}
	selected := make([]keycloak.Realm, 0, len(realms))
	for _, realm := range realms {
		if filter[realm.URLName()] {
			selected = append(selected, realm)
		}
	}
	return selected
}

func discoverImportedRealm(ctx context.Context, kc *keycloak.Client, realm keycloak.Realm, includeIdentityProviders bool) (importedRealmData, *importDiscoveryError) {
	realmName := realm.URLName()
	apps, err := kc.ListApps(ctx, realmName)
	if err != nil {
		return importedRealmData{}, &importDiscoveryError{
			reason:  "ListAppsError",
			message: fmt.Sprintf("cannot list clients in realm %q: %v", realmName, err),
			cause:   fmt.Errorf("list apps in realm %q: %w", realmName, err),
		}
	}
	clients, accounts := classifyImportedApplications(apps)
	var providers []importedRealmIdentityProvider
	if includeIdentityProviders {
		providers, err = discoverImportedIdentityProviders(ctx, kc, realmName)
		if err != nil {
			return importedRealmData{}, &importDiscoveryError{
				reason:  importIdentityProviderErrorReason(err),
				message: importIdentityProviderErrorMessage(err),
				cause:   err,
			}
		}
	}
	return importedRealmData{realm: realm, clients: clients, accounts: accounts, identityProviders: providers}, nil
}

func classifyImportedApplications(apps []keycloak.App) ([]keycloak.App, []keycloak.App) {
	var clients []keycloak.App
	var accounts []keycloak.App
	for _, application := range apps {
		if keycloakInternalClients[application.ClientID] {
			continue
		}
		if application.ServiceAccountsEnabled {
			accounts = append(accounts, application)
		} else {
			clients = append(clients, application)
		}
	}
	return clients, accounts
}

type identityProviderDiscoveryError struct {
	realm    string
	provider string
	cause    error
}

func (e *identityProviderDiscoveryError) Error() string {
	if e.provider == "" {
		return fmt.Sprintf("list identity providers in realm %q: %v", e.realm, e.cause)
	}
	return fmt.Sprintf("list mappers for identity provider %q in realm %q: %v", e.provider, e.realm, e.cause)
}

func discoverImportedIdentityProviders(ctx context.Context, kc *keycloak.Client, realmName string) ([]importedRealmIdentityProvider, error) {
	providers, err := kc.ListIdentityProviders(ctx, realmName)
	if err != nil {
		return nil, &identityProviderDiscoveryError{realm: realmName, cause: err}
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Alias < providers[j].Alias })
	discovered := make([]importedRealmIdentityProvider, 0, len(providers))
	for _, provider := range providers {
		mappers, err := kc.ListIdentityProviderMappers(ctx, realmName, provider.Alias)
		if err != nil {
			return nil, &identityProviderDiscoveryError{realm: realmName, provider: provider.Alias, cause: err}
		}
		sort.Slice(mappers, func(i, j int) bool { return mappers[i].Name < mappers[j].Name })
		discovered = append(discovered, importedRealmIdentityProvider{provider: provider, mappers: mappers})
	}
	return discovered, nil
}

func importIdentityProviderErrorReason(err error) string {
	if discoveryErr, ok := err.(*identityProviderDiscoveryError); ok && discoveryErr.provider != "" {
		return "ListIdentityProviderMappersError"
	}
	return "ListIdentityProvidersError"
}

func importIdentityProviderErrorMessage(err error) string {
	discoveryErr, ok := err.(*identityProviderDiscoveryError)
	if !ok {
		return err.Error()
	}
	if discoveryErr.provider == "" {
		return fmt.Sprintf("cannot list identity providers in realm %q: %v", discoveryErr.realm, discoveryErr.cause)
	}
	return fmt.Sprintf("cannot list mappers for identity provider %q in realm %q: %v", discoveryErr.provider, discoveryErr.realm, discoveryErr.cause)
}

func importDiscoveryCounts(discovered []importedRealmData) hankoshv1alpha1.ImportCounts {
	counts := hankoshv1alpha1.ImportCounts{Realms: len(discovered)}
	for _, realm := range discovered {
		counts.Applications += len(realm.clients)
		counts.ServiceAccounts += len(realm.accounts)
		counts.IdentityProviders += len(realm.identityProviders)
		counts.IdentityProviderMappers += importedIdentityProviderMapperCount(realm.identityProviders)
	}
	counts.Total = importCountTotal(counts)
	return counts
}

func (r *HankoImportReconciler) completeImportDryRun(ctx context.Context, operation *hankoshv1alpha1.HankoImport, discovered []importedRealmData, patch client.Patch) (ctrl.Result, error) {
	now := metav1.Now()
	operation.Status.Phase = "Done"
	operation.Status.CompletedAt = &now
	setCondition(&operation.Status.Conditions, "ImportReady", metav1.ConditionTrue, "DryRun", "dry-run completed — no CRDs were created")
	if err := r.Status().Patch(ctx, operation, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch status after dry-run: %w", err)
	}
	counts := operation.Status.Discovered
	log.FromContext(ctx).Info("HankoImport dry-run completed", "realms", len(discovered), "apps", counts.Applications, "sas", counts.ServiceAccounts,
		"identityProviders", counts.IdentityProviders, "identityProviderMappers", counts.IdentityProviderMappers)
	return ctrl.Result{}, nil
}

func (r *HankoImportReconciler) applyImport(ctx context.Context, operation *hankoshv1alpha1.HankoImport, discovered []importedRealmData) []string {
	includeClients := operation.Spec.IncludeClients == nil || *operation.Spec.IncludeClients
	includeAccounts := operation.Spec.IncludeServiceAccounts == nil || *operation.Spec.IncludeServiceAccounts
	var applyErrors []string
	for _, realm := range discovered {
		realmName := realm.realm.URLName()
		if err := r.applyRealm(ctx, operation, realm.realm, realm.identityProviders); err != nil {
			applyErrors = append(applyErrors, fmt.Sprintf("realm %s: %v", realmName, err))
		}
		if includeClients {
			applyErrors = r.applyImportedApplications(ctx, operation, realmName, realm.clients, applyErrors)
		}
		if includeAccounts {
			applyErrors = r.applyImportedServiceAccounts(ctx, operation, realmName, realm.accounts, applyErrors)
		}
	}
	return applyErrors
}

func (r *HankoImportReconciler) applyImportedApplications(ctx context.Context, operation *hankoshv1alpha1.HankoImport, realmName string, applications []keycloak.App, applyErrors []string) []string {
	for _, application := range applications {
		if err := r.applyApplication(ctx, operation, realmName, application); err != nil {
			applyErrors = append(applyErrors, fmt.Sprintf("app %s/%s: %v", realmName, application.ClientID, err))
		}
	}
	return applyErrors
}

func (r *HankoImportReconciler) applyImportedServiceAccounts(ctx context.Context, operation *hankoshv1alpha1.HankoImport, realmName string, accounts []keycloak.App, applyErrors []string) []string {
	for _, account := range accounts {
		if err := r.applyServiceAccount(ctx, operation, realmName, account); err != nil {
			applyErrors = append(applyErrors, fmt.Sprintf("sa %s/%s: %v", realmName, account.ClientID, err))
		}
	}
	return applyErrors
}

func (r *HankoImportReconciler) completeImport(ctx context.Context, operation *hankoshv1alpha1.HankoImport, applyErrors []string, patch client.Patch) (ctrl.Result, error) {
	operation.Status.Applied.Total = importCountTotal(operation.Status.Applied)
	operation.Status.Skipped.Total = importCountTotal(operation.Status.Skipped)
	now := metav1.Now()
	operation.Status.Phase = "Done"
	operation.Status.CompletedAt = &now
	if len(applyErrors) > 0 {
		setCondition(&operation.Status.Conditions, "ImportReady", metav1.ConditionTrue, "PartialFailure",
			fmt.Sprintf("import completed with %d error(s): %s", len(applyErrors), strings.Join(applyErrors, "; ")))
	} else {
		setCondition(&operation.Status.Conditions, "ImportReady", metav1.ConditionTrue, "Completed", "import completed successfully")
	}
	if err := r.Status().Patch(ctx, operation, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch status after import: %w", err)
	}
	log.FromContext(ctx).Info("HankoImport completed",
		"applied.realms", operation.Status.Applied.Realms,
		"applied.apps", operation.Status.Applied.Applications,
		"applied.sas", operation.Status.Applied.ServiceAccounts,
		"applied.identityProviders", operation.Status.Applied.IdentityProviders,
		"applied.identityProviderMappers", operation.Status.Applied.IdentityProviderMappers,
		"skipped.total", importCountTotal(operation.Status.Skipped),
		"errors", len(applyErrors))
	return ctrl.Result{}, nil
}

// applyRealm creates a HankoRealm for the discovered Keycloak realm if it does not already exist.
func (r *HankoImportReconciler) applyRealm(ctx context.Context, hi *hankoshv1alpha1.HankoImport, realm keycloak.Realm, providers []importedRealmIdentityProvider) error {
	log := log.FromContext(ctx)

	realmName := realm.URLName()
	obj := &hankoshv1alpha1.HankoRealm{
		ObjectMeta: metav1.ObjectMeta{
			Name:      realmName,
			Namespace: hi.Namespace,
			Labels:    map[string]string{importedByLabel: hi.Name},
		},
		Spec: hankoshv1alpha1.HankoRealmSpec{
			DisplayName:       realm.DisplayName,
			LoginTheme:        realm.LoginTheme,
			IdentityProviders: importedIdentityProviderSpecs(providers),
		},
	}

	var existing hankoshv1alpha1.HankoRealm
	err := r.Get(ctx, types.NamespacedName{Name: realmName, Namespace: hi.Namespace}, &existing)
	if errors.IsNotFound(err) {
		if createErr := r.Create(ctx, obj); createErr != nil {
			return createErr
		}
		log.Info("created HankoRealm (Observe mode)", "realm", realmName)
		hi.Status.Applied.Realms++
		hi.Status.Applied.IdentityProviders += len(providers)
		hi.Status.Applied.IdentityProviderMappers += importedIdentityProviderMapperCount(providers)
		return nil
	}
	if err != nil {
		return err
	}
	log.Info("realm already exists, skipping", "realm", realmName)
	hi.Status.Skipped.Realms++
	hi.Status.Skipped.IdentityProviders += len(providers)
	hi.Status.Skipped.IdentityProviderMappers += importedIdentityProviderMapperCount(providers)
	return nil
}

func importedIdentityProviderSpecs(providers []importedRealmIdentityProvider) []hankoshv1alpha1.RealmIdentityProvider {
	result := make([]hankoshv1alpha1.RealmIdentityProvider, 0, len(providers))
	for _, item := range providers {
		provider := item.provider
		spec := hankoshv1alpha1.RealmIdentityProvider{
			Alias: provider.Alias, DisplayName: provider.DisplayName, ProviderID: provider.ProviderID,
			Enabled: boolPointer(provider.Enabled), TrustEmail: boolPointer(provider.TrustEmail),
			StoreToken: boolPointer(provider.StoreToken), AddReadTokenRoleOnCreate: boolPointer(provider.AddReadTokenRoleOnCreate),
			LinkOnly: boolPointer(provider.LinkOnly), FirstBrokerLoginFlowAlias: provider.FirstBrokerLoginFlowAlias,
			PostBrokerLoginFlowAlias: provider.PostBrokerLoginFlowAlias, Config: sanitizedIdentityProviderConfig(provider.Config),
		}
		for _, mapper := range item.mappers {
			spec.Mappers = append(spec.Mappers, hankoshv1alpha1.RealmIdentityProviderMapper{
				Name: mapper.Name, IdentityProviderMapper: mapper.IdentityProviderMapper,
				Config: sanitizedIdentityProviderConfig(mapper.Config),
			})
		}
		result = append(result, spec)
	}
	return result
}

func sanitizedIdentityProviderConfig(config map[string]string) map[string]string {
	result := make(map[string]string, len(config))
	for key, value := range config {
		normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
		if strings.HasSuffix(normalized, "secret") || strings.HasSuffix(normalized, "password") ||
			strings.HasSuffix(normalized, "privatekey") || strings.HasSuffix(normalized, "apikey") ||
			strings.HasSuffix(normalized, "credential") || strings.HasSuffix(normalized, "credentials") {
			continue
		}
		result[key] = value
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func importedIdentityProviderMapperCount(providers []importedRealmIdentityProvider) int {
	total := 0
	for _, provider := range providers {
		total += len(provider.mappers)
	}
	return total
}

func importCountTotal(counts hankoshv1alpha1.ImportCounts) int {
	return counts.Realms + counts.Applications + counts.ServiceAccounts + counts.IdentityProviders + counts.IdentityProviderMappers
}

func boolPointer(value bool) *bool { return &value }

// appType maps a Keycloak App to its hankoShell application type.
func appType(app keycloak.App) string {
	if app.PublicClient {
		return "spa"
	}
	return "web"
}

// applyApplication creates a HankoApplication for the discovered client if no object —
// under any Kubernetes name — already governs this (realmRef, clientID) pair. Dedup is
// keyed on the logical Keycloak identity, not the generated Kubernetes name, so a
// pre-existing explicit HankoApplication (e.g. hand-authored before the import ran)
// is never shadowed by a second, colliding import object. Newly created objects are
// always Observe-mode: HankoImport must never hand out write authority over a client
// it did not itself decide to manage.
func (r *HankoImportReconciler) applyApplication(ctx context.Context, hi *hankoshv1alpha1.HankoImport, realmID string, app keycloak.App) error {
	log := log.FromContext(ctx)

	var existingForClient hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &existingForClient,
		client.InNamespace(hi.Namespace),
		client.MatchingFields{realmClientIndexKey: realmClientKey(realmID, app.ClientID)},
	); err != nil {
		return fmt.Errorf("check existing objects for realm %q client %q: %w", realmID, app.ClientID, err)
	}
	if len(existingForClient.Items) > 0 {
		log.Info("a HankoApplication already governs this client, skipping import",
			"realm", realmID, "clientID", app.ClientID, "existing", existingForClient.Items[0].Name)
		hi.Status.Skipped.Applications++
		return nil
	}

	name := importResourceName(realmID, app.ClientID)
	obj := &hankoshv1alpha1.HankoApplication{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: hi.Namespace,
			Labels:    map[string]string{importedByLabel: hi.Name},
		},
		Spec: hankoshv1alpha1.HankoApplicationSpec{
			RealmRef:     realmID,
			ClientID:     app.ClientID,
			Type:         appType(app),
			RedirectURIs: app.RedirectURIs,
			Mode:         ModeObserve,
		},
	}

	var existing hankoshv1alpha1.HankoApplication
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: hi.Namespace}, &existing)
	if errors.IsNotFound(err) {
		if createErr := r.Create(ctx, obj); createErr != nil {
			return createErr
		}
		log.Info("created HankoApplication (Observe mode)", "realm", realmID, "clientID", app.ClientID)
		hi.Status.Applied.Applications++
		return nil
	}
	if err != nil {
		return err
	}
	log.Info("application already exists, skipping", "realm", realmID, "clientID", app.ClientID)
	hi.Status.Skipped.Applications++
	return nil
}

// applyServiceAccount creates an observe-only HankoServiceAccount inventory item
// for the discovered M2M client if it does not already exist.
func (r *HankoImportReconciler) applyServiceAccount(ctx context.Context, hi *hankoshv1alpha1.HankoImport, realmID string, app keycloak.App) error {
	log := log.FromContext(ctx)
	if isStaticallyProtectedServiceAccountClient(app.ClientID) ||
		isProtectedControlPlaneClient(r.ProtectedRealm, r.ProtectedClientIDs, realmID, app.ClientID) {
		log.Info("protected client cannot be imported as HankoServiceAccount", "realm", realmID, "clientID", app.ClientID)
		hi.Status.Skipped.ServiceAccounts++
		return nil
	}

	var applications hankoshv1alpha1.HankoApplicationList
	if err := r.List(ctx, &applications, client.InNamespace(hi.Namespace)); err != nil {
		return fmt.Errorf("check HankoApplication ownership for realm %q client %q: %w", realmID, app.ClientID, err)
	}
	for i := range applications.Items {
		application := &applications.Items[i]
		if application.Spec.RealmRef == realmID && strings.TrimSpace(application.Spec.ClientID) == strings.TrimSpace(app.ClientID) {
			log.Info("a HankoApplication already governs this client; skipping service-account import",
				"realm", realmID, "clientID", app.ClientID, "application", application.Name)
			hi.Status.Skipped.ServiceAccounts++
			return nil
		}
	}

	name := importResourceName(realmID, app.ClientID)
	obj := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: hi.Namespace,
			Labels:    map[string]string{importedByLabel: hi.Name},
		},
		Spec: hankoshv1alpha1.HankoServiceAccountSpec{
			RealmRef: realmID,
			ClientID: app.ClientID,
		},
	}

	var existing hankoshv1alpha1.HankoServiceAccount
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: hi.Namespace}, &existing)
	if errors.IsNotFound(err) {
		if createErr := r.Create(ctx, obj); createErr != nil {
			return createErr
		}
		log.Info("created HankoServiceAccount (Observe mode)", "realm", realmID, "clientID", app.ClientID)
		hi.Status.Applied.ServiceAccounts++
		return nil
	}
	if err != nil {
		return err
	}
	log.Info("service account already exists, skipping", "realm", realmID, "clientID", app.ClientID)
	hi.Status.Skipped.ServiceAccounts++
	return nil
}

// SetupWithManager registers the reconciler. HankoImport owns no child resources.
func (r *HankoImportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hankoshv1alpha1.HankoImport{}).
		Complete(r)
}
