package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadauth"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestServiceAccountRotationDurableRecoveryNeverReplaysNativeOperation(t *testing.T) {
	for _, failure := range []string{"native-ack-lost", "native-refused", "output-refused", "output-ack-lost", "Prepared", "OutputPrepared", "Committed"} {
		t.Run(failure, func(t *testing.T) {
			f := newAuthenticationFixture(t)
			f.seedSecretClient()
			f.account.Spec.Authentication = nil
			f.account.Spec.RuntimeMetadata = nil
			policy := &api.SecretRotationPolicy{Enabled: true, IntervalDays: 30}
			f.account.Spec.SecretRotationPolicy = policy
			if f.kube.Update(context.Background(), f.account) != nil {
				t.Fatal("legacy fixture preparation failed")
			}
			source, err := f.r.workloadConnection(context.Background(), "auth", "client-source")
			if err != nil {
				t.Fatal(err)
			}
			original := f.kube
			failed := false
			f.allowRotation = failure != "native-refused"
			f.lostAck = failure == "native-ack-lost"
			f.reconciler.Client = interceptor.NewClient(original.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, o client.Object, p client.Patch, opts ...client.PatchOption) error {
				if !failed {
					trigger := false
					if _, ok := o.(*corev1.Secret); ok && (failure == "output-refused" || failure == "output-ack-lost") {
						trigger = true
					}
					if a, ok := o.(*api.HankoServiceAccount); ok {
						var j serviceAccountRotationJournal
						if workloadauth.Decode(a.Annotations[saRotationJournalKey], &j) == nil && j.Step == failure {
							trigger = true
						}
					}
					if trigger {
						failed = true
						if failure == "output-ack-lost" {
							if err := c.Patch(ctx, o, p, opts...); err != nil {
								return err
							}
						}
						return workloadauth.ErrPrecondition
					}
				}
				return c.Patch(ctx, o, p, opts...)
			}})
			now := metav1.NewTime(time.Now().UTC())
			_ = f.reconciler.durableServiceAccountRotation(context.Background(), f.account, policy, &now, source.client)
			// Lose status and recreate the manager immediately at the failed boundary.
			if original.Get(context.Background(), client.ObjectKeyFromObject(f.account), f.account) != nil {
				t.Fatal("identity read failed")
			}
			f.account.Status = api.HankoServiceAccountStatus{}
			if original.Status().Update(context.Background(), f.account) != nil {
				t.Fatal("status loss failed")
			}
			f.reconciler = &HankoServiceAccountReconciler{Client: original, APIReader: original, OwnershipReader: original, Scheme: original.Scheme()}
			for range 3 {
				if original.Get(context.Background(), client.ObjectKeyFromObject(f.account), f.account) != nil {
					t.Fatal("identity read failed")
				}
				err = f.reconciler.durableServiceAccountRotation(context.Background(), f.account, policy, &now, source.client)
			}
			if f.rotations != 1 {
				t.Fatalf("native rotation count=%d", f.rotations)
			}
			if failure == "native-refused" {
				if err == nil || canonicalServiceAccountSecret(f.canonical()) != f.secret {
					t.Fatal("uncertain/refused native rotation replayed or replaced retained output")
				}
			} else if err != nil || canonicalServiceAccountSecret(f.canonical()) != f.secret || f.account.Status.LastRotated == nil {
				t.Fatal("accepted rotation did not recover once")
			}
			encoded, _ := json.Marshal(f.account)
			if strings.Contains(string(encoded), f.secret) || strings.Contains(string(encoded), "retained-fixture-credential") {
				t.Fatal("credential entered public rotation evidence")
			}
		})
	}
}

func TestUnfinishedSecretRotationBlocksFederatedModeChange(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.seedSecretClient()
	f.account.Annotations = map[string]string{saRotationJournalKey: workloadauth.Encode(serviceAccountRotationJournal{Schema: saRotationSchema, OwnerUID: string(f.account.UID), Generation: f.account.Generation, Step: "Prepared"})}
	if f.kube.Update(context.Background(), f.account) != nil {
		t.Fatal("fixture rotation journal failed")
	}
	f.requestTransition("cutover", "Kubernetes")
	f.runAuthentication(3)
	if f.switches != 0 || f.rotations != 0 || conditionReason(f.account.Status.Conditions, "Synced") != "SecretRotationRecoveryRequired" {
		t.Fatal("pending rotation permitted method change")
	}
}
