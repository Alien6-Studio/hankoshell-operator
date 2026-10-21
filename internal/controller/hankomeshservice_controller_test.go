package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	hankoshv1alpha1 "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
)

func meshServiceScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := hankoshv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func meshServiceClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(meshServiceScheme(t)).
		WithObjects(objects...).
		WithStatusSubresource(&hankoshv1alpha1.HankoMeshService{}).
		Build()
}

func validMeshServiceObjects() (*hankoshv1alpha1.HankoMeshService, []client.Object) {
	registration := &hankoshv1alpha1.HankoMeshService{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "apps", Generation: 5},
		Spec: hankoshv1alpha1.HankoMeshServiceSpec{
			TenantRef: "acme", IdentityRef: "orders-identity", ResourceServerRef: "orders-api",
			ServiceRef: "orders", WorkloadServiceAccountRef: "orders",
			Ports: []hankoshv1alpha1.MeshServicePort{{Protocol: "TCP", Port: 8443}},
		},
	}
	identity := &hankoshv1alpha1.HankoServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "orders-identity", Namespace: "apps", Generation: 2},
		Spec:       hankoshv1alpha1.HankoServiceAccountSpec{RealmRef: "acme", ClientID: "orders-api"},
		Status:     hankoshv1alpha1.HankoServiceAccountStatus{Phase: "Ready", ObservedGeneration: 2},
	}
	resourceServer := &hankoshv1alpha1.HankoResourceServer{
		ObjectMeta: metav1.ObjectMeta{Name: "orders-api", Namespace: "apps", Generation: 3},
		Spec:       hankoshv1alpha1.HankoResourceServerSpec{RealmRef: "acme", Audience: "https://orders.internal"},
		Status:     hankoshv1alpha1.HankoResourceServerStatus{Phase: "Ready", ObservedGeneration: 3},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "apps", UID: types.UID("11111111-1111-1111-1111-111111111111")},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"tier": "api", "app": "orders"},
			Ports:    []corev1.ServicePort{{Protocol: corev1.ProtocolTCP, Port: 8443}},
		},
	}
	account := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "apps", UID: types.UID("22222222-2222-2222-2222-222222222222")},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "orders-0", Namespace: "apps", UID: types.UID("33333333-3333-3333-3333-333333333333"), Labels: map[string]string{"app": "orders", "tier": "api"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "orders"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	tenant := &hankoshv1alpha1.HankoTenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Namespace: "apps", Generation: 4},
		Spec:       hankoshv1alpha1.HankoTenantSpec{IsolationMode: "realm", RealmRef: "acme"},
		Status: hankoshv1alpha1.HankoTenantStatus{
			Phase: "Synced", ObservedGeneration: 4, TenantID: "ten_acme", ClusterID: "cluster-a",
		},
	}
	return registration, []client.Object{registration, identity, resourceServer, service, account, pod, tenant}
}

func reconcileMeshService(t *testing.T, objects ...client.Object) (*hankoshv1alpha1.HankoMeshService, error) {
	t.Helper()
	store := meshServiceClient(t, objects...)
	reconciler := &HankoMeshServiceReconciler{Client: store, NodeReader: store, EgressReader: store}
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "orders", Namespace: "apps"}})
	var actual hankoshv1alpha1.HankoMeshService
	if getErr := store.Get(context.Background(), types.NamespacedName{Name: "orders", Namespace: "apps"}, &actual); getErr != nil {
		t.Fatal(getErr)
	}
	return &actual, err
}

func TestMeshServiceResolvesImmutableHankoAndKubernetesBinding(t *testing.T) {
	_, objects := validMeshServiceObjects()
	actual, err := reconcileMeshService(t, objects...)
	if err != nil {
		t.Fatalf("reconcile valid mesh service: %v", err)
	}
	if actual.Status.Phase != "Ready" || actual.Status.ObservedGeneration != actual.Generation {
		t.Fatalf("unexpected status: %#v", actual.Status)
	}
	if actual.Status.WorkloadID != "orders-api" || actual.Status.Audience != "https://orders.internal" || actual.Status.Realm != "acme" {
		t.Fatalf("unexpected Hanko identity binding: %#v", actual.Status)
	}
	if actual.Status.TenantID != "ten_acme" || actual.Status.ClusterID != "cluster-a" {
		t.Fatalf("unexpected Hub identity binding: %#v", actual.Status)
	}
	if actual.Status.ServiceUID != "11111111-1111-1111-1111-111111111111" || actual.Status.WorkloadServiceAccountUID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("unexpected Kubernetes identity binding: %#v", actual.Status)
	}
	if actual.Status.ReceiverNodeUIDs == nil || len(actual.Status.ReceiverNodeUIDs) != 0 {
		t.Fatalf("unready pods must produce an explicit empty receiver set: %#v", actual.Status.ReceiverNodeUIDs)
	}
	if len(actual.Status.SelectorSHA256) != 64 || actual.Status.LastResolved == nil || len(actual.Status.ResolvedPorts) != 1 {
		t.Fatalf("incomplete resolved binding: %#v", actual.Status)
	}
	if condition := conditionByType(actual.Status.Conditions, "Attested"); condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("Attested condition = %#v", condition)
	}
}

func TestMeshServiceResolvesDirectionalServiceUIDEgress(t *testing.T) {
	registration, objects := validMeshServiceObjects()
	registration.Spec.EnforcementMode = "egressOnly"
	registration.Spec.Egress = []hankoshv1alpha1.MeshServiceEgress{{
		Namespace: "kube-system", ServiceRef: "kube-dns",
		Ports: []hankoshv1alpha1.MeshServicePort{{Protocol: "TCP", Port: 53}, {Protocol: "UDP", Port: 53}},
	}}
	objects = append(objects, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system", UID: types.UID("55555555-5555-5555-5555-555555555555")},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.32.0.10",
			Ports:     []corev1.ServicePort{{Protocol: corev1.ProtocolUDP, Port: 53}, {Protocol: corev1.ProtocolTCP, Port: 53}},
		},
	})

	actual, err := reconcileMeshService(t, objects...)
	if err != nil {
		t.Fatalf("reconcile directional mesh service: %v", err)
	}
	if actual.Status.EnforcementMode != "egressOnly" || len(actual.Status.ResolvedEgress) != 1 {
		t.Fatalf("directional egress was not resolved: %#v", actual.Status)
	}
	egress := actual.Status.ResolvedEgress[0]
	if egress.Namespace != "kube-system" || egress.ServiceName != "kube-dns" ||
		egress.ServiceUID != "55555555-5555-5555-5555-555555555555" || len(egress.Ports) != 2 {
		t.Fatalf("unexpected immutable egress binding: %#v", egress)
	}
}

func TestMeshServiceKeepsAuditOnlyRegistrationReadyWithoutActiveEgress(t *testing.T) {
	registration, objects := validMeshServiceObjects()
	registration.Spec.EnforcementMode = "auditOnly"
	actual, err := reconcileMeshService(t, objects...)
	if err != nil {
		t.Fatalf("reconcile audit-only mesh service: %v", err)
	}
	if actual.Status.Phase != "Ready" || actual.Status.EnforcementMode != "auditOnly" || len(actual.Status.ResolvedEgress) != 0 {
		t.Fatalf("unexpected audit-only status: %#v", actual.Status)
	}
}

func TestMeshServiceRejectsUnsafeDirectionalEgress(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*hankoshv1alpha1.HankoMeshService, *corev1.Service)
	}{
		{"ingress only egress", func(registration *hankoshv1alpha1.HankoMeshService, _ *corev1.Service) {
			registration.Spec.EnforcementMode = "ingressOnly"
		}},
		{"audit only egress", func(registration *hankoshv1alpha1.HankoMeshService, _ *corev1.Service) {
			registration.Spec.EnforcementMode = "auditOnly"
		}},
		{"headless", func(_ *hankoshv1alpha1.HankoMeshService, service *corev1.Service) {
			service.Spec.ClusterIP = corev1.ClusterIPNone
		}},
		{"unexposed port", func(registration *hankoshv1alpha1.HankoMeshService, _ *corev1.Service) {
			registration.Spec.Egress[0].Ports[0].Port = 54
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registration, objects := validMeshServiceObjects()
			registration.Spec.EnforcementMode = "egressOnly"
			registration.Spec.Egress = []hankoshv1alpha1.MeshServiceEgress{{
				Namespace: "kube-system", ServiceRef: "kube-dns",
				Ports: []hankoshv1alpha1.MeshServicePort{{Protocol: "UDP", Port: 53}},
			}}
			dns := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system", UID: types.UID("55555555-5555-5555-5555-555555555555")},
				Spec:       corev1.ServiceSpec{ClusterIP: "10.32.0.10", Ports: []corev1.ServicePort{{Protocol: corev1.ProtocolUDP, Port: 53}}},
			}
			test.mutate(registration, dns)
			objects = append(objects, dns)
			actual, err := reconcileMeshService(t, objects...)
			if err == nil || actual.Status.Phase != "Error" || actual.Status.ResolvedEgress != nil {
				t.Fatalf("unsafe reviewed egress accepted: status=%#v err=%v", actual.Status, err)
			}
		})
	}
}

func TestMeshServiceResolvesReadyPodNodeByImmutableUID(t *testing.T) {
	_, objects := validMeshServiceObjects()
	pod := objects[5].(*corev1.Pod)
	pod.Spec.NodeName = "worker-a"
	pod.Status.Conditions = []corev1.PodCondition{{
		Type: corev1.PodReady, Status: corev1.ConditionTrue,
	}}
	objects = append(objects, &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: "worker-a", UID: types.UID("44444444-4444-4444-4444-444444444444"),
	}})

	actual, err := reconcileMeshService(t, objects...)
	if err != nil {
		t.Fatalf("reconcile ready mesh receiver: %v", err)
	}
	if len(actual.Status.ReceiverNodeUIDs) != 1 || actual.Status.ReceiverNodeUIDs[0] != "44444444-4444-4444-4444-444444444444" {
		t.Fatalf("receiver nodes were not bound to immutable Node UIDs: %#v", actual.Status.ReceiverNodeUIDs)
	}
}

func TestMeshServiceRemovesTerminatingReadyPodFromReceiverSet(t *testing.T) {
	_, objects := validMeshServiceObjects()
	pod := objects[5].(*corev1.Pod)
	pod.Spec.NodeName = "worker-a"
	pod.Status.Conditions = []corev1.PodCondition{{
		Type: corev1.PodReady, Status: corev1.ConditionTrue,
	}}
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	pod.Finalizers = []string{"test.hanko.sh/hold"}

	actual, err := reconcileMeshService(t, objects...)
	if err != nil {
		t.Fatalf("reconcile terminating receiver: %v", err)
	}
	if actual.Status.ReceiverNodeUIDs == nil || len(actual.Status.ReceiverNodeUIDs) != 0 {
		t.Fatalf("terminating pod retained receiver authority: %#v", actual.Status.ReceiverNodeUIDs)
	}
}

func TestMeshServiceFailsClosedWhenReadyPodNodeCannotBeAttested(t *testing.T) {
	tests := []struct {
		name string
		node *corev1.Node
	}{
		{name: "node absent"},
		{name: "node UID absent", node: &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-a"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, objects := validMeshServiceObjects()
			pod := objects[5].(*corev1.Pod)
			pod.Spec.NodeName = "worker-a"
			pod.Status.Conditions = []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue,
			}}
			if test.node != nil {
				objects = append(objects, test.node)
			}

			actual, err := reconcileMeshService(t, objects...)
			if err == nil || actual.Status.Phase != "Error" || actual.Status.ReceiverNodeUIDs != nil {
				t.Fatalf("unattested receiver node accepted: status=%#v err=%v", actual.Status, err)
			}
		})
	}
}

func TestMeshServiceRejectsStaleHankoIdentityGeneration(t *testing.T) {
	registration, objects := validMeshServiceObjects()
	registration.Status = hankoshv1alpha1.HankoMeshServiceStatus{
		Phase: "Ready", WorkloadID: "stale", Audience: "stale", Realm: "stale", ServiceUID: "stale",
		TenantID: "stale", ClusterID: "stale", WorkloadServiceAccountUID: "stale", SelectorSHA256: strings.Repeat("a", 64),
	}
	identity := objects[1].(*hankoshv1alpha1.HankoServiceAccount)
	identity.Generation = 3
	identity.Status.ObservedGeneration = 2

	actual, err := reconcileMeshService(t, objects...)
	if err == nil {
		t.Fatal("stale Hanko identity status was accepted")
	}
	if actual.Status.Phase != "Error" || actual.Status.TenantID != "" || actual.Status.ClusterID != "" || actual.Status.WorkloadID != "" || actual.Status.Realm != "" || actual.Status.ServiceUID != "" || actual.Status.SelectorSHA256 != "" {
		t.Fatalf("stale resolved identity was not cleared: %#v", actual.Status)
	}
}

func TestMeshServiceRejectsSelectedPodIdentitySpoofing(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*corev1.Pod)
	}{
		{"wrong service account", func(pod *corev1.Pod) { pod.Spec.ServiceAccountName = "attacker" }},
		{"terminating wrong service account", func(pod *corev1.Pod) {
			now := metav1.Now()
			pod.DeletionTimestamp = &now
			pod.Finalizers = []string{"test.hanko.sh/hold"}
			pod.Spec.ServiceAccountName = "attacker"
		}},
		{"host network", func(pod *corev1.Pod) { pod.Spec.HostNetwork = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, objects := validMeshServiceObjects()
			test.mutate(objects[5].(*corev1.Pod))
			actual, err := reconcileMeshService(t, objects...)
			if err == nil || actual.Status.Phase != "Error" {
				t.Fatalf("spoofing accepted: status=%#v err=%v", actual.Status, err)
			}
		})
	}
}

func TestMeshServiceRejectsUnboundOrAmbiguousNetworkTargets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]client.Object)
	}{
		{"external name", func(objects []client.Object) {
			objects[3].(*corev1.Service).Spec.Type = corev1.ServiceTypeExternalName
		}},
		{"empty selector", func(objects []client.Object) {
			objects[3].(*corev1.Service).Spec.Selector = nil
		}},
		{"unexposed port", func(objects []client.Object) {
			objects[0].(*hankoshv1alpha1.HankoMeshService).Spec.Ports[0].Port = 9443
		}},
		{"duplicate port", func(objects []client.Object) {
			registration := objects[0].(*hankoshv1alpha1.HankoMeshService)
			registration.Spec.Ports = append(registration.Spec.Ports, registration.Spec.Ports[0])
		}},
		{"realm mismatch", func(objects []client.Object) {
			objects[2].(*hankoshv1alpha1.HankoResourceServer).Spec.RealmRef = "other"
		}},
		{"foreign tenant realm", func(objects []client.Object) {
			objects[6].(*hankoshv1alpha1.HankoTenant).Spec.RealmRef = "victim"
		}},
		{"unlabelled dedicated tenant identity", func(objects []client.Object) {
			objects[6].(*hankoshv1alpha1.HankoTenant).Spec.IsolationMode = "cluster"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, objects := validMeshServiceObjects()
			test.mutate(objects)
			actual, err := reconcileMeshService(t, objects...)
			if err == nil || actual.Status.Phase != "Error" {
				t.Fatalf("invalid target accepted: status=%#v err=%v", actual.Status, err)
			}
		})
	}
}

func TestMeshServiceAcceptsExplicitDedicatedTenantLabels(t *testing.T) {
	_, objects := validMeshServiceObjects()
	objects[6].(*hankoshv1alpha1.HankoTenant).Spec.IsolationMode = "cluster"
	objects[1].(*hankoshv1alpha1.HankoServiceAccount).Labels = map[string]string{"hanko.sh/tenant": "acme"}
	objects[2].(*hankoshv1alpha1.HankoResourceServer).Labels = map[string]string{"hanko.sh/tenant": "acme"}
	actual, err := reconcileMeshService(t, objects...)
	if err != nil || actual.Status.Phase != "Ready" {
		t.Fatalf("explicit dedicated tenant binding rejected: status=%#v err=%v", actual.Status, err)
	}
}

func TestServiceSelectorHashIsCanonical(t *testing.T) {
	left := hashServiceSelector(map[string]string{"tier": "api", "app": "orders"})
	right := hashServiceSelector(map[string]string{"app": "orders", "tier": "api"})
	changed := hashServiceSelector(map[string]string{"app": "orders", "tier": "worker"})
	if left != right || left == changed || len(left) != 64 {
		t.Fatalf("selector hash is not canonical: left=%s right=%s changed=%s", left, right, changed)
	}
}

func conditionByType(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for index := range conditions {
		if conditions[index].Type == conditionType {
			return &conditions[index]
		}
	}
	return nil
}
