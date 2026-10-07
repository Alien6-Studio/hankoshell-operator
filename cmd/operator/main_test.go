package main

import (
	"flag"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func TestManagerOptionsConfineCacheAndLeaderElection(t *testing.T) {
	const namespace = "auth"

	opts := managerOptions(":8080", ":8081", true, namespace)

	if len(opts.Cache.DefaultNamespaces) != 1 {
		t.Fatalf("DefaultNamespaces length = %d, want 1", len(opts.Cache.DefaultNamespaces))
	}
	if _, ok := opts.Cache.DefaultNamespaces[namespace]; !ok {
		t.Fatalf("DefaultNamespaces = %#v, want namespace %q", opts.Cache.DefaultNamespaces, namespace)
	}
	if _, ok := opts.Cache.DefaultNamespaces[cache.AllNamespaces]; ok {
		t.Fatal("DefaultNamespaces must not contain cache.AllNamespaces")
	}
	if opts.LeaderElectionNamespace != namespace {
		t.Fatalf("LeaderElectionNamespace = %q, want %q", opts.LeaderElectionNamespace, namespace)
	}
	if opts.Client.Cache == nil || len(opts.Client.Cache.DisableFor) != 1 {
		t.Fatalf("client cache exclusions = %#v, want Secret only", opts.Client.Cache)
	}
	if _, ok := opts.Client.Cache.DisableFor[0].(*corev1.Secret); !ok {
		t.Fatalf("client cache exclusion = %T, want *corev1.Secret", opts.Client.Cache.DisableFor[0])
	}
}

func TestParseRuntimeConfigRequiresExplicitNamespaceAndHonorsFlags(t *testing.T) {
	originalArgs := os.Args
	originalFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalFlags
	})
	flag.CommandLine = flag.NewFlagSet("operator-test", flag.ContinueOnError)
	os.Args = []string{
		"operator", "--metrics-bind-address=:9090", "--health-probe-bind-address=:9091",
		"--leader-elect=false", "--watch-namespace= auth ",
	}

	config := parseRuntimeConfig()
	if config.metricsAddr != ":9090" || config.probeAddr != ":9091" {
		t.Fatalf("unexpected listener configuration: %#v", config)
	}
	if config.enableLeaderElection || config.watchNamespace != "auth" {
		t.Fatalf("unexpected runtime configuration: %#v", config)
	}
}

func TestDeploymentConfiguration(t *testing.T) {
	t.Setenv("HANKO_KEYCLOAK_DEPLOYMENT", "")
	if got := keycloakDeploymentName(); got != "keycloak" {
		t.Fatalf("default Keycloak deployment = %q", got)
	}
	t.Setenv("HANKO_KEYCLOAK_DEPLOYMENT", "identity")
	if got := keycloakDeploymentName(); got != "identity" {
		t.Fatalf("configured Keycloak deployment = %q", got)
	}
}

func TestDefaultMetricsDoNotCreateAServer(t *testing.T) {
	originalArgs, originalFlags := os.Args, flag.CommandLine
	t.Cleanup(func() {
		os.Args, flag.CommandLine = originalArgs, originalFlags
	})
	flag.CommandLine = flag.NewFlagSet("operator-test", flag.ContinueOnError)
	os.Args = []string{"operator", "--watch-namespace=auth"}
	config := parseRuntimeConfig()
	if config.metricsAddr != "0" || config.probeAddr != ":8081" {
		t.Fatalf("unexpected default listener configuration: %#v", config)
	}
	opts := managerOptions(config.metricsAddr, config.probeAddr, true, "auth")
	server, err := metricsserver.NewServer(opts.Metrics, nil, nil)
	if err != nil || server != nil {
		t.Fatalf("disabled metrics created a server: %v, %v", server, err)
	}
}

func TestControlPlaneAuthorizedClientIDsAreNormalizedAndDeduplicated(t *testing.T) {
	t.Setenv("HANKO_CONTROL_PLANE_AUTHORIZED_CLIENTS", " hanko-dashboard, support-dashboard,hanko-dashboard, ,CaseSensitive ")
	got := controlPlaneAuthorizedClientIDs()
	want := []string{"hanko-dashboard", "support-dashboard", "CaseSensitive"}
	if len(got) != len(want) {
		t.Fatalf("client IDs = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("client IDs = %#v, want %#v", got, want)
		}
	}
}

func TestFleetAuthorityRealmIsNormalized(t *testing.T) {
	t.Setenv("HANKO_FLEET_AUTHORITY_REALM", " alien6 ")
	if got := fleetAuthorityRealm(); got != "alien6" {
		t.Fatalf("fleet authority realm = %q, want alien6", got)
	}
}

func TestEnterpriseProfileRequiresExplicitRelayAndHTTPSIntegrations(t *testing.T) {
	for _, name := range []string{"HANKO_SECURITY_PROFILE", "HANKO_ENTERPRISE_HUB_ENDPOINT", "HANKO_CONTINUUM_HUB_ADDRESS", "HANKO_ENTERPRISE_ENROLLMENT_ENDPOINT", "HANKO_KEYCLOAK_URL", "HANKO_API_URL", "HANKO_SUPERVISION_API_URL", "HANKO_SPOKE_MODE"} {
		t.Setenv(name, "")
	}
	policy, err := enterprisePolicyFromEnv()
	if err != nil || policy != nil {
		t.Fatalf("standard profile should remain independent: %v", err)
	}
	t.Setenv("HANKO_SECURITY_PROFILE", "unknown")
	if _, err := enterprisePolicyFromEnv(); err == nil {
		t.Fatal("unknown security profile accepted")
	}
	t.Setenv("HANKO_SECURITY_PROFILE", "enterprise")
	if _, err := enterprisePolicyFromEnv(); err == nil {
		t.Fatal("enterprise profile accepted a missing private relay")
	}
	t.Setenv("HANKO_ENTERPRISE_HUB_ENDPOINT", "https://hub.mesh.example:9443")
	t.Setenv("HANKO_CONTINUUM_HUB_ADDRESS", "10.250.0.1")
	if policy, err := enterprisePolicyFromEnv(); err != nil || policy == nil {
		t.Fatalf("valid enterprise configuration rejected: %v", err)
	}
	for _, name := range []string{"HANKO_API_URL", "HANKO_SUPERVISION_API_URL", "HANKO_KEYCLOAK_URL"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "http://service.auth.svc")
			if _, err := enterprisePolicyFromEnv(); err == nil {
				t.Fatal("enterprise profile accepted an HTTP integration")
			}
		})
	}
}
