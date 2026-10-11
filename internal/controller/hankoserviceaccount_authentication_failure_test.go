package controller

import (
	"context"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadauth"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func (f *authenticationFixture) federateReviewed() {
	f.t.Helper()
	f.seedSecretClient()
	f.requestTransition("first-federation", "Kubernetes")
	f.runAuthentication(3)
	f.approve()
	f.runAuthentication(1)
	f.review(true)
	f.runAuthentication(2)
	if f.account.Status.Phase != "Ready" {
		f.t.Fatal("fixture federation not ready")
	}
}

func (f *authenticationFixture) canonical() *corev1.Secret {
	f.t.Helper()
	var secret corev1.Secret
	if f.kube.Get(context.Background(), client.ObjectKey{Namespace: f.account.Namespace, Name: saSecretName(f.account.Spec.ClientID)}, &secret) != nil {
		f.t.Fatal("canonical output missing")
	}
	return &secret
}

func TestFallbackFailureMatrixPreservesWorkingFederatedAuthenticator(t *testing.T) {
	for _, failure := range []string{"missing-native", "denied-native", "immutable-output", "foreign-output", "write-denied", "replaced-output", "revoked-approval", "lost-output-ack"} {
		t.Run(failure, func(t *testing.T) {
			f := newAuthenticationFixture(t)
			f.federateReviewed()
			f.requestTransition("fallback", "Secret")
			original := f.kube
			switch failure {
			case "missing-native":
				f.secret = ""
			case "denied-native":
				f.denyRecovery = true
			case "immutable-output", "foreign-output":
				s := f.canonical()
				if failure == "immutable-output" {
					immutable := true
					s.Immutable = &immutable
				} else {
					s.OwnerReferences = nil
				}
				if original.Update(context.Background(), s) != nil {
					t.Fatal("fixture mutation failed")
				}
			case "write-denied", "lost-output-ack":
				f.reconciler.Client = interceptor.NewClient(original.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, o client.Object, p client.Patch, opts ...client.PatchOption) error {
					if _, ok := o.(*corev1.Secret); ok {
						if failure == "lost-output-ack" {
							if err := c.Patch(ctx, o, p, opts...); err != nil {
								return err
							}
						}
						return workloadauth.ErrPrecondition
					}
					return c.Patch(ctx, o, p, opts...)
				}})
			}
			f.runAuthentication(3)
			if failure == "replaced-output" {
				s := f.canonical()
				if original.Delete(context.Background(), s) != nil {
					t.Fatal("fixture delete failed")
				}
				s.ResourceVersion = ""
				s.UID = "replaced-canonical"
				if original.Create(context.Background(), s) != nil {
					t.Fatal("fixture replacement failed")
				}
				f.approve()
				f.runAuthentication(2)
			}
			if failure == "revoked-approval" {
				f.approve()
				delete(f.account.Annotations, workloadauth.ApprovalKey)
				if original.Update(context.Background(), f.account) != nil {
					t.Fatal("fixture revoke failed")
				}
				f.runAuthentication(2)
			}
			if f.switches != 1 || f.rotations != 0 || f.dependents[0]["clientAuthenticatorType"] != "federated-jwt" {
				t.Fatal("failed/unapproved fallback changed working native method")
			}
			if failure == "lost-output-ack" {
				if canonicalServiceAccountSecret(f.canonical()) != f.secret || f.journal().SecretUID != "canonical-uid" {
					t.Fatal("accepted output not recovered")
				}
				f.approve()
				f.runAuthentication(3)
				if f.switches != 2 || f.account.Status.Phase != "Ready" {
					t.Fatal("lost output ACK fallback did not commit")
				}
			}
		})
	}
}

func TestAuthenticationCleanupRejectsStaleReviewAndUnexpectedNativeState(t *testing.T) {
	for _, failure := range []string{"request", "client", "binding", "workload", "plan", "secret-uid", "foreign-secret", "native-drift", "unknown-security"} {
		t.Run(failure, func(t *testing.T) {
			f := newAuthenticationFixture(t)
			f.seedSecretClient()
			f.requestTransition("cutover", "Kubernetes")
			f.runAuthentication(3)
			f.approve()
			f.runAuthentication(1)
			f.review(true)
			var review workloadauth.Review
			_ = workloadauth.Decode(f.account.Annotations[workloadauth.ReviewKey], &review)
			switch failure {
			case "request":
				review.RequestID = "foreign"
			case "client":
				review.ClientUUID = "foreign"
			case "binding":
				review.BindingRevision = workloadauth.Hash("foreign", 1)
			case "workload":
				review.WorkloadUID = "foreign"
			case "plan":
				review.PlanHash = workloadauth.Hash("foreign", 1)
			case "secret-uid":
				var c workloadauth.Cleanup
				_ = workloadauth.Decode(f.account.Annotations[workloadauth.CleanupKey], &c)
				c.SecretUID = "foreign"
				f.account.Annotations[workloadauth.CleanupKey] = workloadauth.Encode(c)
			case "foreign-secret":
				s := f.canonical()
				s.OwnerReferences = nil
				if f.kube.Update(context.Background(), s) != nil {
					t.Fatal("fixture mutation failed")
				}
			case "native-drift":
				f.dependents[0]["attributes"].(map[string]any)["locale"] = "en"
			case "unknown-security":
				f.dependents[0]["unqualifiedSecuritySetting"] = true
			}
			f.account.Annotations[workloadauth.ReviewKey] = workloadauth.Encode(review)
			if f.kube.Update(context.Background(), f.account) != nil {
				t.Fatal("fixture approval mutation failed")
			}
			f.runAuthentication(2)
			if canonicalServiceAccountSecret(f.canonical()) != f.secret || f.account.Status.Phase == "Ready" || f.switches != 1 || f.rotations != 0 {
				t.Fatal("stale/unknown state authorized cleanup")
			}
		})
	}
}

func TestAuthenticationCleanupRecoversPartialPatchAndManagerRestart(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "refused", true: "accepted-ack-lost"}[lost], func(t *testing.T) {
			f := newAuthenticationFixture(t)
			f.seedSecretClient()
			f.requestTransition("cutover", "Kubernetes")
			f.runAuthentication(3)
			f.approve()
			f.runAuthentication(1)
			f.review(true)
			original := f.kube
			once := true
			f.reconciler.Client = interceptor.NewClient(original.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, o client.Object, p client.Patch, opts ...client.PatchOption) error {
				if _, ok := o.(*corev1.Secret); ok && once {
					once = false
					if lost {
						if err := c.Patch(ctx, o, p, opts...); err != nil {
							return err
						}
					}
					return workloadauth.ErrPrecondition
				}
				return c.Patch(ctx, o, p, opts...)
			}})
			f.runAuthentication(1)
			f.account.Status = api.HankoServiceAccountStatus{}
			if original.Status().Update(context.Background(), f.account) != nil {
				t.Fatal("status loss simulation failed")
			}
			f.reconciler = &HankoServiceAccountReconciler{Client: original, APIReader: original, OwnershipReader: original, RuntimeClient: original, WorkloadTrust: f.r, Scheme: original.Scheme()}
			f.runAuthentication(5)
			if f.account.Status.Phase != "Ready" || f.switches != 1 || f.rotations != 0 || canonicalServiceAccountSecret(f.canonical()) != "" || string(f.canonical().Data["unrelated"]) != "preserved" {
				t.Fatal("partial cleanup/restart recovery changed unrelated data or repeated switch")
			}
		})
	}
}

func TestObserveFederatedIdentityHasNoNativeCredentialJournalOrOutputWrites(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.nativeClient("foreign-owner")
	f.account.Spec.Mode = "Observe"
	if f.kube.Update(context.Background(), f.account) != nil {
		t.Fatal("fixture Observe failed")
	}
	f.runAuthentication(3)
	if f.creates != 0 || f.switches != 0 || f.rotations != 0 || f.credentialRoutes != 0 || f.account.Annotations[workloadauth.JournalKey] != "" || f.runtime.Data["workload-identity.json"] != "" {
		t.Fatal("Observe performed authentication or output writes")
	}
	if metav1.IsControlledBy(f.canonicalIfPresent(), f.account) {
		t.Fatal("Observe created an owned canonical output")
	}
}

func (f *authenticationFixture) canonicalIfPresent() *corev1.Secret {
	var s corev1.Secret
	_ = f.kube.Get(context.Background(), client.ObjectKey{Namespace: f.account.Namespace, Name: saSecretName(f.account.Spec.ClientID)}, &s)
	return &s
}

func TestForgedAbsentJournalCannotAuthorizeExistingSecretCutover(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.seedSecretClient()
	f.requestTransition("cutover", "Kubernetes")
	f.runAuthentication(3)
	j := f.journal()
	j.PreviousMode = "Absent"
	s, err := f.r.serviceAccountWorkloadSnapshot(context.Background(), f.account, false)
	if err != nil {
		t.Fatal(err)
	}
	j.PlanHash = authenticationTransactionPlanHash(f.account, s, *j)
	f.account.Annotations[workloadauth.JournalKey] = workloadauth.Encode(j)
	if f.kube.Update(context.Background(), f.account) != nil {
		t.Fatal("fixture journal update failed")
	}
	f.runAuthentication(3)
	if f.switches != 0 || f.dependents[0]["clientAuthenticatorType"] != "client-secret" {
		t.Fatal("forged creation journal bypassed native mode proof")
	}
}

func TestConcurrentFederatedMappingDoesNotAuthorizeAnotherClient(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.nativeClient("foreign-owner")
	f.dependents[0]["clientId"] = "other-client"
	f.runAuthentication(3)
	if f.creates != 0 || f.switches != 0 || f.account.Status.Phase == "Ready" || conditionReason(f.account.Status.Conditions, "Synced") != "AmbiguousFederatedWorkloadMapping" {
		t.Fatalf("ambiguous mapping boundary: create=%d switch=%d phase=%s reason=%s", f.creates, f.switches, f.account.Status.Phase, conditionReason(f.account.Status.Conditions, "Synced"))
	}
}

func TestContainedClientRequiresNewReviewedActivation(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.runAuthentication(4)
	f.dependents[0]["enabled"] = false
	f.account.Generation++
	if err := f.kube.Update(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	f.runAuthentication(3)
	if f.dependents[0]["enabled"] != false || f.account.Status.Phase == "Ready" || f.switches != 0 {
		t.Fatal("a generation change automatically reactivated contained identity")
	}
	f.requestTransition("reviewed-reactivation", "Kubernetes")
	f.runAuthentication(3)
	f.approve()
	f.runAuthentication(1)
	if f.dependents[0]["enabled"] != true || f.account.Status.Phase == "Ready" || f.journal().Step != "ModeApplied" {
		t.Fatal("reactivation skipped the external authentication review")
	}
	f.review(false)
	j := f.journal()
	r := workloadauth.Review{RequestID: j.RequestID, ClientUUID: j.ClientUUID, BindingRevision: j.BindingRevision, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash}
	f.account.Annotations[workloadauth.CleanupKey] = workloadauth.Encode(workloadauth.Cleanup{Review: r, SecretUID: "reviewed-absent-output"})
	if err := f.kube.Update(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	f.runAuthentication(3)
	if f.account.Status.Phase != "Ready" || f.switches != 1 || f.creates != 1 || f.credentialRoutes != 0 || f.journal().Step != "Committed" {
		t.Fatal("reviewed reactivation did not retain the native identity without credentials")
	}
}

func TestFederatedGenericAttributeUpdateRecoversAcknowledgementWithoutMethodWrite(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.runAuthentication(4)
	f.account.Spec.Attributes = map[string]string{"locale": "fr"}
	f.account.Generation++
	if err := f.kube.Update(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	f.lostAck = true
	f.runAuthentication(4)
	if f.account.Status.Phase != "Ready" || f.creates != 1 || f.switches != 0 || f.credentialRoutes != 0 || f.clientWrites != 1 {
		t.Fatal("generic attribute update repeated a native write or changed authentication")
	}
	attrs := f.dependents[0]["attributes"].(map[string]any)
	if attrs["locale"] != "fr" || attrs["jwt.credential.issuer"] != "cluster" || attrs["jwt.credential.sub"] != workloadSubject(f.account) {
		t.Fatal("partial generic update changed the qualified native mapping")
	}
}

func TestAuthenticationTransitionFreshDependencyDriftStopsMutationAndCleanup(t *testing.T) {
	for _, after := range []bool{false, true} {
		for _, failure := range []string{"flow", "provider-uuid", "native-uuid", "native-state", "source", "reader", "trust-generation", "workload-uid", "consent"} {
			t.Run(map[bool]string{false: "before-", true: "after-"}[after]+failure, func(t *testing.T) {
				f := newAuthenticationFixture(t)
				f.seedSecretClient()
				f.requestTransition("cutover", "Kubernetes")
				f.runAuthentication(3)
				f.approve()
				if after {
					f.runAuthentication(1)
					f.review(true)
				}
				switch failure {
				case "flow":
					f.failure = "disabled flow"
				case "provider-uuid":
					f.provider["internalId"] = "replacement-provider"
				case "native-uuid":
					f.dependents[0]["id"] = "replacement-native"
				case "native-state":
					f.dependents[0]["unknownSecuritySetting"] = true
				case "source", "reader":
					name := "client-source"
					if failure == "reader" {
						name = "reader"
					}
					var secret corev1.Secret
					if f.kube.Get(context.Background(), client.ObjectKey{Namespace: "auth", Name: name}, &secret) != nil {
						t.Fatal("fixture source missing")
					}
					secret.Annotations = map[string]string{"reviewed-version": "changed"}
					if f.kube.Update(context.Background(), &secret) != nil {
						t.Fatal("fixture source change failed")
					}
				case "trust-generation":
					f.update(func(trust *api.HankoWorkloadTrust) {
						trust.Spec.Kubernetes.AssertionMaxAgeSeconds = 900
						trust.Generation++
					})
				case "workload-uid":
					f.replaceWorkload()
				case "consent":
					delete(f.runtime.Annotations, "hanko.sh/workload-runtime-owner-uid")
					if f.kube.Update(context.Background(), f.runtime) != nil {
						t.Fatal("fixture consent revocation failed")
					}
				}
				f.runAuthentication(3)
				want := 0
				if after {
					want = 1
				}
				if f.switches != want || f.rotations != 0 || canonicalServiceAccountSecret(f.canonical()) != f.secret || f.account.Status.Phase == "Ready" {
					t.Fatalf("dependency drift %s crossed transaction boundary", failure)
				}
			})
		}
	}
}

func TestFederatedOwnedDeletionRecoversAcknowledgementAndPreservesForeignGraph(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned-lost-ack", true: "foreign-authorization"}[foreign], func(t *testing.T) {
			f := newAuthenticationFixture(t)
			f.account.Spec.RuntimeMetadata = nil
			if f.kube.Update(context.Background(), f.account) != nil {
				t.Fatal("fixture metadata intent failed")
			}
			f.runAuthentication(4)
			if f.account.Status.Phase != "Ready" {
				t.Fatal("fresh fixture not activated")
			}
			if foreign {
				f.dependents[0]["authorizationServicesEnabled"] = true
			}
			f.lostAck = true
			if f.kube.Delete(context.Background(), f.account) != nil {
				t.Fatal("fixture delete failed")
			}
			for range 3 {
				_, err := f.reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.account)})
				if err != nil {
					t.Fatal(err)
				}
			}
			if foreign {
				if f.nativeDeletes != 0 || f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.account), f.account) != nil || len(f.account.Finalizers) == 0 {
					t.Fatal("foreign graph was deleted or lifecycle guard removed")
				}
			} else if f.nativeDeletes != 1 || len(f.dependents) != 0 || !apierrors.IsNotFound(f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.account), f.account)) {
				t.Fatal("owned deletion did not converge exactly once")
			}
			if f.credentialRoutes != 0 || f.rotations != 0 {
				t.Fatal("federated cleanup crossed credential boundary")
			}
		})
	}
}
