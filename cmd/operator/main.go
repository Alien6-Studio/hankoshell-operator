package main

import (
	"flag"
	"net/http"
	"os"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/controller"
	"github.com/Alien6-Studio/hankoshell-operator/internal/decommission"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hankoapi"
	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/observability"
	"github.com/Alien6-Studio/hankoshell-operator/internal/selfupdate"
	"github.com/Alien6-Studio/hankoshell-operator/internal/supervision"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var scheme = runtime.NewScheme()

const (
	operatorRecorderName = "hanko-operator"
	controllerSetupError = "unable to create controller"
)

type runtimeConfig struct {
	metricsAddr          string
	metricsCertDir       string
	metricsClientCA      string
	metricsClientURIs    string
	probeAddr            string
	watchNamespace       string
	enableLeaderElection bool
	enableLifecycle      bool
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
	projection, err := newPositionProjector()
	fatalIfError(err, "invalid organization projection configuration")
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
	if hubPolicy != nil && projection.Mode == hankoapi.ProjectionEnabled {
		fatalIfError(projection.Client.RequireHTTPS(), "enterprise organization transport is invalid")
	}
	managerConfig := managerOptions(
		config.metricsAddr,
		config.probeAddr,
		config.enableLeaderElection,
		config.watchNamespace,
	)
	if config.metricsAddr != "0" {
		secureTLS, tlsErr := observability.MetricsTLS(config.metricsCertDir, config.metricsClientCA, strings.Split(config.metricsClientURIs, ","))
		fatalIfError(tlsErr, "invalid metrics TLS configuration")
		managerConfig.Metrics.TLSOpts = append(managerConfig.Metrics.TLSOpts, secureTLS)
	}
	observability.Default.Register(metrics.Registry)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerConfig)
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
	setupControllers(mgr, pool, projection, config.watchNamespace, hubHTTPClient, meshPolicyClient, meshPolicyNamespace, hubPolicy, config.enableLifecycle)
	setupHealthChecks(mgr, kc, config.watchNamespace, config.metricsAddr != "0")

	ctrl.Log.Info("starting hanko-operator", "watchNamespace", config.watchNamespace)
	fatalIfError(mgr.Start(ctrl.SetupSignalHandler()), "problem running manager")
}

func parseRuntimeConfig() runtimeConfig {
	config := runtimeConfig{}
	flag.StringVar(&config.metricsAddr, "metrics-bind-address", "0", "Address for the metrics endpoint; 0 disables it.")
	flag.StringVar(&config.metricsCertDir, "metrics-cert-dir", "", "Directory with metrics server tls.crt and tls.key; required when metrics are enabled.")
	flag.StringVar(&config.metricsClientCA, "metrics-client-ca", "", "PEM CA file for metrics client authentication.")
	flag.StringVar(&config.metricsClientURIs, "metrics-client-uris", "", "Comma-separated exact SPIFFE client URI SAN allowlist (maximum 16).")
	flag.StringVar(&config.probeAddr, "health-probe-bind-address", ":8081", "Address for the health probe endpoint.")
	flag.BoolVar(&config.enableLeaderElection, "leader-elect", true, "Enable leader election for controller manager.")
	flag.BoolVar(&config.enableLifecycle, "lifecycle-enabled", false, "Enable experimental operations and snapshots; requires independent approval admission protection.")
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

type organizationProjectionRuntime struct {
	Mode   hankoapi.ProjectionMode
	Client *hankoapi.PositionClient
}

func newPositionProjector() (organizationProjectionRuntime, error) {
	value, present := os.LookupEnv("HANKO_ORGANIZATION_PROJECTION_ENABLED")
	apiURL, token := os.Getenv("HANKO_API_URL"), os.Getenv("HANKO_API_TOKEN")
	mode, legacy, err := hankoapi.NormalizeProjectionMode(value, present, apiURL, token)
	configuration := organizationProjectionRuntime{Mode: mode}
	if err != nil || mode == hankoapi.ProjectionDisabled {
		return configuration, err
	}
	configuration.Client, err = hankoapi.NewPositionClient(apiURL, token, nil)
	if err == nil && legacy {
		ctrl.Log.Info("legacy organization projection configuration; set HANKO_ORGANIZATION_PROJECTION_ENABLED=true explicitly")
	}
	return configuration, err
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
	projection organizationProjectionRuntime,
	watchNamespace string,
	hubHTTPClient *http.Client,
	meshPolicyClient client.Client,
	meshPolicyNamespace string,
	hubPolicy *hub.ContinuumPolicy,
	lifecycleEnabled bool,
) {
	applicationSecretProjectionClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	fatalIfError(err, "unable to initialise application secret projection client")
	protectedClientIDs := controlPlaneAuthorizedClientIDs()
	protectedRealm := fleetAuthorityRealm()
	workloadTrust := &controller.HankoWorkloadTrustReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), ClusterConfig: mgr.GetConfig()}
	fatalIfError(workloadTrust.SetupWithManager(mgr), controllerSetupError, "controller", "HankoWorkloadTrust")
	fatalIfError((&controller.HankoIAMProfileReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoIAMProfile")
	fatalIfError((&controller.HankoRealmReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), ProtectedRealm: protectedRealm, Scheme: mgr.GetScheme(), Pool: pool, Recorder: observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName))}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoRealm")
	fatalIfError((&controller.HankoEmailProviderReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoEmailProvider")
	fatalIfError((&controller.HankoIssuerReconciler{
		Client:            mgr.GetClient(),
		APIDeploymentName: os.Getenv("HANKO_API_DEPLOYMENT"),
		APIContainerName:  os.Getenv("HANKO_API_CONTAINER"),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoIssuer")
	fatalIfError((&controller.HankoApplicationReconciler{
		Client: mgr.GetClient(), OwnershipReader: mgr.GetAPIReader(), SecretProjectionClient: applicationSecretProjectionClient, RuntimeClient: applicationSecretProjectionClient,
		ProtectedClientIDs: protectedClientIDs, ProtectedRealm: protectedRealm,
		ExperimentalAuthentik:            os.Getenv("HANKO_EXPERIMENTAL_AUTHENTIK_ENABLED") == "true",
		ExperimentalAuthentikConnections: strings.Split(os.Getenv("HANKO_EXPERIMENTAL_AUTHENTIK_CONNECTIONS"), ","),
		Scheme:                           mgr.GetScheme(), Pool: pool, Recorder: observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName)),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoApplication")
	fatalIfError((&controller.HankoServiceAccountReconciler{
		APIReader: mgr.GetAPIReader(), RuntimeClient: applicationSecretProjectionClient, WorkloadTrust: workloadTrust,
		Client: mgr.GetClient(), OwnershipReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), Pool: pool,
		Recorder: observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName)), ProtectedClientIDs: protectedClientIDs, ProtectedRealm: protectedRealm,
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoServiceAccount")
	fatalIfError((&controller.HankoRoleReconciler{Client: mgr.GetClient(), ProtectedRealm: protectedRealm, Scheme: mgr.GetScheme(), Pool: pool, Recorder: observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName))}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoRole")
	organizationReconciler := &controller.HankoOrganizationReconciler{Client: mgr.GetClient(), ProtectedRealm: protectedRealm, Scheme: mgr.GetScheme(), Pool: pool, Recorder: observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName)), ProjectionMode: projection.Mode}
	// Keep an unavailable client visibly nil; the installation mode remains
	// independent and enabled reconciliation reports ProjectorUnavailable.
	if projection.Client != nil {
		organizationReconciler.Positions = projection.Client
	}
	fatalIfError(organizationReconciler.SetupWithManager(mgr), controllerSetupError, "controller", "HankoOrganization")
	fatalIfError((&controller.HankoResourceServerReconciler{Client: mgr.GetClient(), WorkloadTrust: workloadTrust, Scheme: mgr.GetScheme(), Pool: pool, Recorder: observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName))}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoResourceServer")
	fatalIfError((&controller.HankoMeshServiceReconciler{
		APIReader: mgr.GetAPIReader(), WorkloadTrust: workloadTrust,
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
		Recorder:               observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName)),
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoTheme")
	fatalIfError((&controller.HankoTenantReconciler{
		Recorder:                     observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName)),
		Client:                       mgr.GetClient(),
		ClusterIdentityReader:        mgr.GetAPIReader(),
		Scheme:                       mgr.GetScheme(),
		Pool:                         pool,
		Supervision:                  supervision,
		HubHTTPClient:                hubHTTPClient,
		HubTransportPolicy:           hubPolicy,
		FleetTrustConfigMapName:      os.Getenv("HANKO_FLEET_TRUST_CONFIGMAP"),
		MeshPolicyConfigMapName:      os.Getenv("HANKO_MESH_POLICY_CONFIGMAP_NAME"),
		MeshPolicyConfigMapNamespace: meshPolicyNamespace,
		MeshPolicyProjectionClient:   meshPolicyClient,
		Decommission:                 decommissionConfig(watchNamespace),
		AgentUpdate:                  agentUpdateConfig(watchNamespace),
		ImageValidator:               imgValidator,
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoTenant")
	serviceAccountMaxAge, err := controller.ParseServiceAccountMaxAge(os.Getenv("HANKO_KC_SA_MAX_AGE"))
	fatalIfError(err, "invalid Keycloak service-account rotation configuration")
	rotationAudit := newCredentialRotationAuditor()
	if hubPolicy != nil && rotationAudit != nil {
		fatalIfError(rotationAudit.RequireHTTPS(), "enterprise audit transport is invalid")
	}
	fatalIfError((&controller.HankoKeycloakInstanceReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(), ImageValidator: imgValidator,
		Recorder: observability.SafeRecorder(mgr.GetEventRecorder(operatorRecorderName)), CredentialRotationAudit: rotationAudit,
		ServiceAccountMaxAge: serviceAccountMaxAge,
		RequireHTTPS:         hubPolicy != nil,
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoKeycloakInstance")
	fatalIfError((&controller.HankoImportReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Pool: pool,
		ProtectedClientIDs: protectedClientIDs, ProtectedRealm: protectedRealm,
		RequireHTTPS: hubPolicy != nil,
	}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoImport")
	if lifecycleEnabled {
		fatalIfError((&controller.HankoSnapshotReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(), ImageValidator: imgValidator,
		}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoSnapshot")
		fatalIfError((&controller.HankoOperationReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr), controllerSetupError, "controller", "HankoOperation")
	}
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
			BindAddress:   metricsAddr,
			SecureServing: true,
		},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "hanko-operator.hanko.sh",
		LeaderElectionNamespace: watchNamespace,
	}
}
