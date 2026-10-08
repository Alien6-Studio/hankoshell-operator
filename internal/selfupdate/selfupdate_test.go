package selfupdate

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
)

const testDigest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

type releaseVerifier struct {
	calls          int
	image, version string
	err            error
}

func (v *releaseVerifier) VerifyOperatorImage(_ context.Context, image, version string) error {
	v.calls++
	v.image, v.version = image, version
	return v.err
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func operatorDeployment(image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "auth", Name: "hanko-operator"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "kube-rbac-proxy", Image: "quay.io/brancz/kube-rbac-proxy:v0.15.0"},
					{Name: "manager", Image: image},
				}},
			},
		},
	}
}

func engineFor(t *testing.T, deployment *appsv1.Deployment) *Engine {
	t.Helper()
	builder := fake.NewClientBuilder().WithScheme(testScheme(t))
	if deployment != nil {
		builder = builder.WithObjects(deployment)
	}
	kube := builder.Build()
	return &Engine{
		Writer:   kube,
		Reader:   kube,
		Config:   Config{Namespace: "auth", DeploymentName: "hanko-operator", ContainerName: "manager"},
		Verifier: &releaseVerifier{},
	}
}

func TestRunRequiresVerificationEvenWhenAlreadyPinned(t *testing.T) {
	image := "registry.example/operator@" + testDigest
	for _, verifier := range []ReleaseVerifier{nil, &releaseVerifier{err: errors.New("untrusted credential=hidden")}} {
		engine := engineFor(t, operatorDeployment(image))
		engine.Verifier = verifier
		if _, err := engine.Run(context.Background(), &hub.AgentUpdateCommand{Version: "0.1.0", Digest: testDigest}); err == nil || strings.Contains(err.Error(), "hidden") {
			t.Fatalf("verification did not fail closed/redact: %v", err)
		}
		if managerImage(t, engine) != image {
			t.Fatal("denied update changed the deployment")
		}
	}
	engine := engineFor(t, operatorDeployment("registry.example/operator:old"))
	verifier := &releaseVerifier{}
	engine.Verifier = verifier
	if _, err := engine.Run(context.Background(), &hub.AgentUpdateCommand{Version: "0.1.0", Digest: testDigest}); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 || verifier.image != image || verifier.version != "0.1.0" {
		t.Fatalf("lost release binding: %+v", verifier)
	}
}

type conflictingWriter struct{ client.Client }

func (w conflictingWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	var current appsv1.Deployment
	if err := w.Get(ctx, client.ObjectKeyFromObject(object), &current); err != nil {
		return err
	}
	current.Spec.Template.Spec.Containers[1].Image = "registry.example/operator:admin-change"
	if err := w.Update(ctx, &current); err != nil {
		return err
	}
	return w.Client.Patch(ctx, object, patch, options...)
}

func TestRunDoesNotOverwriteConcurrentAdministratorChange(t *testing.T) {
	engine := engineFor(t, operatorDeployment("registry.example/operator:old"))
	engine.Writer = conflictingWriter{engine.Writer}
	if _, err := engine.Run(context.Background(), &hub.AgentUpdateCommand{Version: "0.1.0", Digest: testDigest}); err == nil {
		t.Fatal("stale update overwrote an administrator change")
	}
	if managerImage(t, engine) != "registry.example/operator:admin-change" {
		t.Fatal("concurrent change was lost")
	}
}

func managerImage(t *testing.T, e *Engine) string {
	t.Helper()
	var deployment appsv1.Deployment
	if err := e.Reader.Get(context.Background(), types.NamespacedName{Namespace: "auth", Name: "hanko-operator"}, &deployment); err != nil {
		t.Fatal(err)
	}
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == "manager" {
			return container.Image
		}
	}
	t.Fatal("manager container not found")
	return ""
}

func TestRunPinsDigestAndPreservesRepository(t *testing.T) {
	cases := map[string]struct {
		image string
		want  string
	}{
		"plain tag": {
			image: "hankodev.azurecr.io/hanko-operator:0ldbu1ld",
			want:  "hankodev.azurecr.io/hanko-operator@" + testDigest,
		},
		"registry with port keeps its port": {
			image: "registry.example.com:5000/fleet/hanko-operator:0ldbu1ld",
			want:  "registry.example.com:5000/fleet/hanko-operator@" + testDigest,
		},
		"existing digest pin is replaced": {
			image: "hankodev.azurecr.io/hanko-operator@sha256:" + strings.Repeat("0", 64),
			want:  "hankodev.azurecr.io/hanko-operator@" + testDigest,
		},
		"tag plus digest collapses to the new digest": {
			image: "hankodev.azurecr.io/hanko-operator:0ldbu1ld@sha256:" + strings.Repeat("0", 64),
			want:  "hankodev.azurecr.io/hanko-operator@" + testDigest,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			engine := engineFor(t, operatorDeployment(tc.image))
			pinned, err := engine.Run(context.Background(), &hub.AgentUpdateCommand{Version: "defc534", Digest: testDigest})
			if err != nil {
				t.Fatal(err)
			}
			if pinned != tc.want {
				t.Fatalf("pinned image = %q, want %q", pinned, tc.want)
			}
			if got := managerImage(t, engine); got != tc.want {
				t.Fatalf("deployment image = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRunIsIdempotentWhenAlreadyPinned(t *testing.T) {
	engine := engineFor(t, operatorDeployment("hankodev.azurecr.io/hanko-operator@"+testDigest))
	pinned, err := engine.Run(context.Background(), &hub.AgentUpdateCommand{Version: "defc534", Digest: testDigest})
	if err != nil || pinned != "hankodev.azurecr.io/hanko-operator@"+testDigest {
		t.Fatalf("idempotent run: image=%q err=%v", pinned, err)
	}
}

func TestRunRefusesInvalidCommands(t *testing.T) {
	cases := map[string]*hub.AgentUpdateCommand{
		"nil command":       nil,
		"missing version":   {Digest: testDigest},
		"missing digest":    {Version: "defc534"},
		"tag as digest":     {Version: "defc534", Digest: "defc534"},
		"uppercase digest":  {Version: "defc534", Digest: "sha256:" + strings.Repeat("A", 64)},
		"truncated digest":  {Version: "defc534", Digest: "sha256:" + strings.Repeat("a", 63)},
		"unsupported algo":  {Version: "defc534", Digest: "sha512:" + strings.Repeat("a", 64)},
		"trailing metadata": {Version: "defc534", Digest: testDigest + "?x"},
	}
	for name, command := range cases {
		t.Run(name, func(t *testing.T) {
			engine := engineFor(t, operatorDeployment("hankodev.azurecr.io/hanko-operator:0ldbu1ld"))
			if _, err := engine.Run(context.Background(), command); err == nil {
				t.Fatal("expected an error, got none")
			}
			if got := managerImage(t, engine); got != "hankodev.azurecr.io/hanko-operator:0ldbu1ld" {
				t.Fatalf("deployment must stay untouched, image = %q", got)
			}
		})
	}
}

func TestRunReportsMissingTargets(t *testing.T) {
	command := &hub.AgentUpdateCommand{Version: "defc534", Digest: testDigest}

	if _, err := engineFor(t, nil).Run(context.Background(), command); err == nil {
		t.Fatal("expected an error for a missing deployment")
	}

	engine := engineFor(t, operatorDeployment("hankodev.azurecr.io/hanko-operator:0ldbu1ld"))
	engine.Config.ContainerName = "sidecar"
	if _, err := engine.Run(context.Background(), command); err == nil {
		t.Fatal("expected an error for an unknown container")
	}

	engine = engineFor(t, operatorDeployment("hankodev.azurecr.io/hanko-operator:0ldbu1ld"))
	engine.Config.DeploymentName = " "
	if _, err := engine.Run(context.Background(), command); err == nil {
		t.Fatal("expected a validation error for a blank deployment name")
	}
}
