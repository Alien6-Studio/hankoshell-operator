package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/decommission"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/selfupdate"
	"github.com/Alien6-Studio/hankoshell-operator/internal/supervision"
)

var scheme = runtime.NewScheme()

const (
	operatorRecorderName = "hanko-operator"
	controllerSetupError = "unable to create controller"
)

type runtimeConfig struct {
	metricsAddr          string
	probeAddr            string
	watchNamespace       string
	enableLeaderElection bool
}

func init() { //nolint:gochecknoinits // controller-runtime requires scheme registration before manager startup.
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(hankoshv1alpha1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(batchv1.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
}

// spokeMode reports whether the operator runs on a spoke cluster that only
// syncs Hub bundles and has no co-located Keycloak (HANKO_SPOKE_MODE=true).
func spokeMode() bool {
	return os.Getenv("HANKO_SPOKE_MODE") == "true"
}

func main() {
	config := parseRuntimeConfig()
	hubPolicy, err := enterprisePolicyFromEnv()
	fatalIfError(err, "invalid operator security profile")
	var kc *keycloak.Client
	if spokeMode() {
		// No Keycloak on spoke clusters: keep a client pointing at an invalid
		// host so realm-scoped reconciliations fail loudly instead of at nil.
		kc = keycloak.New("https://keycloak.invalid", "", "")
	} else {
		var err error
		kc, err = keycloak.NewFromEnv()
		fatalIfError(err, "unable to initialise Keycloak client")
	}
	if hubPolicy != nil {
		fatalIfError(kc.RequireHTTPS(), "enterprise Keycloak transport is invalid")
	}
	pool := keycloak.NewPool(kc)
	positions := newPositionProjector()
	if hubPolicy != nil && positions != nil {
		fatalIfError(positions.RequireHTTPS(), "enterprise organization transport is invalid")
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions(
		config.metricsAddr,
		config.probeAddr,
		config.enableLeaderElection,
		config.watchNamespace,
	))
	fatalIfError(err, "unable to start manager")

	hubHTTPClient, err := hub.NewHTTPClient(os.Getenv("HANKO_HUB_CA_FILE"))
	if err == nil && hubPolicy != nil {
		hubHTTPClient, err = hubPolicy.HTTPClient(os.Getenv("HANKO_HUB_CA_FILE"))
	}
	fatalIfError(err, "unable to initialise Hub synchronization client")
	meshPolicyNamespace := strings.TrimSpace(os.Getenv("HANKO_MESH_POLICY_CONFIGMAP_NAMESPACE"))
	meshPolicyClient := mgr.GetClient()
	if meshPolicyNamespace != "" && meshPolicyNamespace != config.watchNamespace {
		meshPolicyClient, err = client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
		fatalIfError(err, "unable to initialise cross-namespace mesh policy projection client")
	}
	setupControllers(mgr, pool, positions, config.watchNamespace, hubHTTPClient, meshPolicyClient, meshPolicyNamespace, hubPolicy)
	setupHealthChecks(mgr, kc)

	ctrl.Log.Info("starting hanko-operator", "watchNamespace", config.watchNamespace)
	fatalIfError(mgr.Start(ctrl.SetupSignalHandler()), "problem running manager")
}

func parseRuntimeConfig() runtimeConfig {
	config := runtimeConfig{}
	flag.StringVar(&config.metricsAddr, "metrics-bind-address", "0", "Address for the metrics endpoint; 0 disables it.")
	flag.StringVar(&config.probeAddr, "health-probe-bind-address", ":8081", "Address for the health probe endpoint.")
	flag.BoolVar(&config.enableLeaderElection, "leader-elect", true, "Enable leader election for controller manager.")
	flag.StringVar(&config.watchNamespace, "watch-namespace", os.Getenv("WATCH_NAMESPACE"), "Required namespace watched and managed by the operator.")
	opts := zap.Options{Development: os.Getenv("HANKO_LOG_DEV") == "true"}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	config.watchNamespace = strings.TrimSpace(config.watchNamespace)
	if config.watchNamespace == "" {
		ctrl.Log.Error(nil, "--watch-namespace is required; refusing cluster-wide operation")
		os.Exit(1)
	}
	return config
}

func newPositionProjector() *hankoapi.PositionClient {
	apiURL := strings.TrimSpace(os.Getenv("HANKO_API_URL"))
	if apiURL == "" {
		return nil
	}
	client, err := hankoapi.NewPositionClient(apiURL, os.Getenv("HANKO_API_TOKEN"), nil)
	fatalIfError(err, "unable to initialise Hanko organization projector")
	return client
}

func keycloakDeploymentName() string {
	name := os.Getenv("HANKO_KEYCLOAK_DEPLOYMENT")
	if name == "" {
		return "keycloak"
	}
	return name
}

func controlPlaneAuthorizedClientIDs() []string {
	seen := make(map[string]struct{})
	clientIDs := make([]string, 0)
	for _, raw := range strings.Split(os.Getenv("HANKO_CONTROL_PLANE_AUTHORIZED_CLIENTS"), ",") {
		clientID := strings.TrimSpace(raw)
		if clientID == "" {
			continue
		}
		if _, duplicate := seen[clientID]; duplicate {
			continue
		}
		seen[clientID] = struct{}{}
		clientIDs = append(clientIDs, clientID)
	}
	return clientIDs
}

func fleetAuthorityRealm() string {
	return strings.TrimSpace(os.Getenv("HANKO_FLEET_AUTHORITY_REALM"))
}

// supervisionCollector builds the collector attached to Hub heartbeats. The
// local API summary is fetched only when both HANKO_SUPERVISION_API_URL and
// HANKO_SUPERVISION_API_TOKEN are set; otherwise the collector reports the
// operator-native Keycloak instance health only.
func supervisionCollector(mgr ctrl.Manager, watchNamespace string) *supervision.Collector {
	return supervision.New(
		mgr.GetClient(),
		watchNamespace,
		os.Getenv("HANKO_SUPERVISION_API_URL"),
		os.Getenv("HANKO_SUPERVISION_API_TOKEN"),
	)
}

func setupControllers(
	mgr ctrl.Manager,
	pool *keycloak.Pool,
	positions *hankoapi.PositionClient,
	watchNamespace string,
	hubHTTPClient *http.Client,
	meshPolicyClient client.Client,
	meshPolicyNamespace string,
	hubPolicy *hub.ContinuumPolicy,
) {
	applicationSecretProjectionClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	fatalIfError(err, "unable to initialise application secret projection client")
	protectedClientIDs := controlPlaneAuthorizedClientIDs()
	protectedRealm := fleetAuthorityRealm()
	fatalIfError((&controller.HankoIAMProfileReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoIAMProfile")
	fatalIfError((&controller.HankoRealmReconciler{Client: mgr.GetClient(), ProtectedRealm: protectedRealm, Scheme: mgr.GetScheme(), Pool: pool, Recorder: mgr.GetEventRecorder(operatorRecorderName)}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoRealm")
	fatalIfError((&controller.HankoEmailProviderReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoEmailProvider")
	fatalIfError((&controller.HankoIssuerReconciler{
		Client:            mgr.GetClient(),
		APIDeploymentName: os.Getenv("HANKO_API_DEPLOYMENT"),
		APIContainerName:  os.Getenv("HANKO_API_CONTAINER"),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoIssuer")
	fatalIfError((&controller.HankoApplicationReconciler{
		Client: mgr.GetClient(), OwnershipReader: mgr.GetAPIReader(), SecretProjectionClient: applicationSecretProjectionClient,
		ProtectedClientIDs: protectedClientIDs, ProtectedRealm: protectedRealm,
		Scheme: mgr.GetScheme(), Pool: pool, Recorder: mgr.GetEventRecorder(operatorRecorderName),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoApplication")
	fatalIfError((&controller.HankoServiceAccountReconciler{
		Client: mgr.GetClient(), OwnershipReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), Pool: pool,
		Recorder: mgr.GetEventRecorder(operatorRecorderName), ProtectedClientIDs: protectedClientIDs, ProtectedRealm: protectedRealm,
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoServiceAccount")
	fatalIfError((&controller.HankoRoleReconciler{Client: mgr.GetClient(), ProtectedRealm: protectedRealm, Scheme: mgr.GetScheme(), Pool: pool, Recorder: mgr.GetEventRecorder(operatorRecorderName)}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoRole")
	organizationReconciler := &controller.HankoOrganizationReconciler{Client: mgr.GetClient(), ProtectedRealm: protectedRealm, Scheme: mgr.GetScheme(), Pool: pool, Recorder: mgr.GetEventRecorder(operatorRecorderName)}
	// Assign only a live projector: storing a nil *PositionClient in the
	// interface field would defeat the reconciler's nil check (typed nil) and
	// panic instead of failing closed with ProjectorUnavailable.
	if positions != nil {
		organizationReconciler.Positions = positions
	}
	fatalIfError(organizationReconciler.SetupWithManager(mgr), controllerSetupError, "controller", "HankoOrganization")
	fatalIfError((&controller.HankoResourceServerReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Pool: pool, Recorder: mgr.GetEventRecorder(operatorRecorderName)}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoResourceServer")
	fatalIfError((&controller.HankoMeshServiceReconciler{
		Client: mgr.GetClient(), NodeReader: mgr.GetAPIReader(), EgressReader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoMeshService")
	imgValidator := imagevalidator.NewWithPolicy(os.Getenv("HANKO_IMAGE_POLICY_FILE"), &imagevalidator.CosignVerifier{
		Binary: "/usr/local/bin/cosign", DockerConfig: os.Getenv("HANKO_IMAGE_VERIFY_DOCKER_CONFIG"),
	})
	supervision := supervisionCollector(mgr, watchNamespace)
	if hubPolicy != nil {
		fatalIfError(supervision.RequireHTTPS(), "enterprise supervision transport is invalid")
	}
	fatalIfError((&controller.HankoThemeReconciler{
		Client:                 mgr.GetClient(),
		Scheme:                 mgr.GetScheme(),
		KeycloakDeploymentName: keycloakDeploymentName(),
		ImageValidator:         imgValidator,
		Recorder:               mgr.GetEventRecorder(operatorRecorderName),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoTheme")
	fatalIfError((&controller.HankoTenantReconciler{
		Client:                       mgr.GetClient(),
		ClusterIdentityReader:        mgr.GetAPIReader(),
		Scheme:                       mgr.GetScheme(),
		Pool:                         pool,
		Supervision:                  supervision,
		HubHTTPClient:                hubHTTPClient,
		HubTransportPolicy:           hubPolicy,
		MeshPolicyConfigMapName:      os.Getenv("HANKO_MESH_POLICY_CONFIGMAP_NAME"),
		MeshPolicyConfigMapNamespace: meshPolicyNamespace,
		MeshPolicyProjectionClient:   meshPolicyClient,
		Decommission:                 decommissionConfig(watchNamespace),
		AgentUpdate:                  agentUpdateConfig(watchNamespace),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoTenant")
	serviceAccountMaxAge, err := controller.ParseServiceAccountMaxAge(os.Getenv("HANKO_KC_SA_MAX_AGE"))
	fatalIfError(err, "invalid Keycloak service-account rotation configuration")
	rotationAudit := newCredentialRotationAuditor()
	if hubPolicy != nil && rotationAudit != nil {
		fatalIfError(rotationAudit.RequireHTTPS(), "enterprise audit transport is invalid")
	}
	fatalIfError((&controller.HankoKeycloakInstanceReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(), ImageValidator: imgValidator,
		Recorder: mgr.GetEventRecorder(operatorRecorderName), CredentialRotationAudit: rotationAudit,
		ServiceAccountMaxAge: serviceAccountMaxAge,
		RequireHTTPS:         hubPolicy != nil,
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoKeycloakInstance")
	fatalIfError((&controller.HankoImportReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Pool: pool,
		ProtectedClientIDs: protectedClientIDs, ProtectedRealm: protectedRealm,
		RequireHTTPS: hubPolicy != nil,
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoImport")
	fatalIfError((&controller.HankoSnapshotReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoSnapshot")
	fatalIfError((&controller.HankoOperationReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoOperation")
}

// decommissionConfig reads the Helm-provided identity of this release for the
// Hub-driven self-uninstall. An empty HANKO_DECOMMISSION_RELEASE disables the
// feature: the reconciler then refuses decommission commands and Hub keeps
// them pending for a reviewed manual uninstall.
func decommissionConfig(watchNamespace string) *decommission.Config {
	release := strings.TrimSpace(os.Getenv("HANKO_DECOMMISSION_RELEASE"))
	if release == "" {
		return nil
	}
	config := &decommission.Config{
		Namespace: watchNamespace, ReleaseName: release,
		CiliumPolicy: os.Getenv("HANKO_CILIUM_POLICY_ENABLED") == "true",
	}
	for _, name := range strings.Split(os.Getenv("HANKO_DECOMMISSION_DISPOSABLE_SECRETS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			config.CASecretNames = append(config.CASecretNames, name)
		}
	}
	config.Transport = transportDecommissionConfig()
	return config
}

// transportDecommissionConfig reads the Helm-provided identity of the
// Continuum tenant transport release. Leaving HANKO_DECOMMISSION_TRANSPORT_RELEASE
// empty keeps transport-backed tenants fail-closed: their decommission is
// refused and stays pending on Hub.
func transportDecommissionConfig() *decommission.TransportConfig {
	release := strings.TrimSpace(os.Getenv("HANKO_DECOMMISSION_TRANSPORT_RELEASE"))
	namespace := strings.TrimSpace(os.Getenv("HANKO_DECOMMISSION_TRANSPORT_NAMESPACE"))
	if release == "" || namespace == "" {
		return nil
	}
	transport := &decommission.TransportConfig{Namespace: namespace, ReleaseName: release}
	for _, name := range strings.Split(os.Getenv("HANKO_DECOMMISSION_TRANSPORT_SECRETS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			transport.SecretNames = append(transport.SecretNames, name)
		}
	}
	return transport
}

// agentUpdateConfig reads the Helm-provided identity of this operator's own
// Deployment for the Hub-commanded digest-pinned self-update. An empty
// HANKO_AGENT_UPDATE_DEPLOYMENT disables the feature: the reconciler then
// refuses update commands and Hub keeps them pending for a reviewed manual
// release rollout.
func agentUpdateConfig(watchNamespace string) *selfupdate.Config {
	deployment := strings.TrimSpace(os.Getenv("HANKO_AGENT_UPDATE_DEPLOYMENT"))
	if deployment == "" {
		return nil
	}
	container := strings.TrimSpace(os.Getenv("HANKO_AGENT_UPDATE_CONTAINER"))
	if container == "" {
		container = "manager"
	}
	return &selfupdate.Config{Namespace: watchNamespace, DeploymentName: deployment, ContainerName: container}
}

func newCredentialRotationAuditor() *hankoapi.AuditClient {
	apiURL := strings.TrimSpace(os.Getenv("HANKO_SUPERVISION_API_URL"))
	token := strings.TrimSpace(os.Getenv("HANKO_SUPERVISION_API_TOKEN"))
	if apiURL == "" && token == "" {
		return nil
	}
	client, err := hankoapi.NewAuditClient(apiURL, token, nil)
	fatalIfError(err, "unable to initialise Keycloak credential rotation audit client")
	return client
}

func setupHealthChecks(mgr ctrl.Manager, kc *keycloak.Client) {
	fatalIfError(mgr.AddHealthzCheck("healthz", healthz.Ping), "unable to set up health check")
	fatalIfError(mgr.AddReadyzCheck("readyz", healthz.Ping), "unable to set up ready check")
	if spokeMode() {
		return
	}
	fatalIfError(mgr.AddReadyzCheck("keycloak", func(_ *http.Request) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := kc.ServerVersion(ctx)
		return err
	}), "unable to set up keycloak ready check")
}

func fatalIfError(err error, message string, keysAndValues ...any) {
	if err != nil {
		ctrl.Log.Error(err, message, keysAndValues...)
		os.Exit(1)
	}
}

func managerOptions(metricsAddr, probeAddr string, enableLeaderElection bool, watchNamespace string) ctrl.Options {
	return ctrl.Options{
		Scheme: scheme,
		Client: client.Options{Cache: &client.CacheOptions{
			// Secrets are credentials, not controller state. Every read must hit
			// the API server and Secrets must never be retained in the shared cache.
			DisableFor: []client.Object{&corev1.Secret{}},
		}},
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				watchNamespace: {},
			},
		},
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "hanko-operator.hanko.sh",
		LeaderElectionNamespace: watchNamespace,
	}
}
