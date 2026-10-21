package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Alien6-Studio/hankoshell-operator/internal/hub"
	"github.com/Alien6-Studio/hankoshell-operator/internal/imagevalidator"
	"github.com/Alien6-Studio/hankoshell-operator/internal/selfupdate"
	"github.com/Alien6-Studio/hankoshell-operator/internal/version"
)

func TestTenantAgentUpdateUsesIndependentImageApproval(t *testing.T) {
	for _, name := range []string{"missing policy", "signature denied", "version spoof", "approved"} {
		t.Run(name, func(t *testing.T) {
			tenant := decommissionTestTenant("")
			deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "operator", Namespace: tenant.Namespace}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "manager", Image: "registry.example/hanko/operator:previous"}}}}}}
			kube := controllerTestClient(controllerTestScheme(t), tenant, deployment)
			var validator *imagevalidator.Validator
			if name != "missing policy" {
				validator = approvedFixtureValidator(t)
			}
			if name == "signature denied" {
				validator = fixtureValidator(t, fixtureSignatureVerifier{err: errors.New("untrusted")})
			}
			r := &HankoTenantReconciler{Client: kube, ClusterIdentityReader: kube, ImageValidator: validator, AgentUpdate: &selfupdate.Config{Namespace: tenant.Namespace, DeploymentName: deployment.Name, ContainerName: "manager"}}
			command := &hub.AgentUpdateCommand{Version: "0.1.0", Digest: strings.Split(approvedOperatorImage, "@")[1]}
			if name == "version spoof" {
				command.Version = version.Agent
			}
			result, err := r.executeAgentUpdate(context.Background(), tenant, client.MergeFrom(tenant.DeepCopy()), nil, command)
			if err != nil {
				t.Fatal(err)
			}
			var current appsv1.Deployment
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(deployment), &current); err != nil {
				t.Fatal(err)
			}
			if name == "approved" {
				if current.Spec.Template.Spec.Containers[0].Image != approvedOperatorImage || result.RequeueAfter != requeueInterval {
					t.Fatal("approved update was not applied")
				}
			} else {
				if current.Spec.Template.Spec.Containers[0].Image != deployment.Spec.Template.Spec.Containers[0].Image {
					t.Fatal("unapproved update changed operator image")
				}
				assertTenantIdentityError(t, kube, tenant, "AgentUpdateFailed")
			}
		})
	}
}
