package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadauth"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadbinding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type authenticationFixture struct {
	*bindingFixture
	creates, switches, rotations, nativeDeletes int
	secret                                      string
	denyRecovery                                bool
	allowRotation                               bool
}

func newAuthenticationFixture(t *testing.T) *authenticationFixture {
	f := &authenticationFixture{bindingFixture: newBindingFixture(t), secret: "retained-fixture-credential"}
	f.reconciler.Scheme = f.kube.Scheme()
	previous := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer client-source" || !strings.HasPrefix(r.URL.Path, "/admin/realms/managed/clients") {
			previous.ServeHTTP(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/protocol-mappers/models") && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]any{})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/client-secret") {
			f.credentialRoutes++
			if r.Method == http.MethodPost {
				f.rotations++
				if f.allowRotation {
					f.secret = "rotated-fixture-credential"
					if f.lostAck {
						lostHTTPAcknowledgement(w)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"value": f.secret})
					return
				}
				w.WriteHeader(403)
				return
			}
			if f.denyRecovery {
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"value": f.secret})
			return
		}
		if r.URL.Path == "/admin/realms/managed/clients" && r.Method == http.MethodPost {
			f.mu.Lock()
			defer f.mu.Unlock()
			var native map[string]any
			if json.NewDecoder(r.Body).Decode(&native) != nil || native["clientAuthenticatorType"] != "federated-jwt" || native["serviceAccountsEnabled"] != true || native["fullScopeAllowed"] != false || native["secret"] != nil {
				t.Error("invalid fresh federated client payload")
				w.WriteHeader(400)
				return
			}
			if len(f.dependents) != 0 {
				t.Error("duplicate CREATE")
				w.WriteHeader(409)
				return
			}
			f.dependents = []map[string]any{native}
			f.creates++
			if f.lostAck {
				lostHTTPAcknowledgement(w)
				return
			}
			w.WriteHeader(201)
			return
		}
		if r.Method == http.MethodPut {
			f.mu.Lock()
			defer f.mu.Unlock()
			var payload map[string]any
			if json.NewDecoder(r.Body).Decode(&payload) != nil {
				w.WriteHeader(400)
				return
			}
			for _, native := range f.dependents {
				if r.URL.Path == "/admin/realms/managed/clients/"+native["id"].(string) {
					if payload["clientAuthenticatorType"] != nil {
						if payload["serviceAccountsEnabled"] != nil || payload["secret"] != nil {
							t.Error("cutover resent independent state")
							w.WriteHeader(400)
							return
						}
						f.switches++
					}
					for k, v := range payload {
						if k == "attributes" {
							encoded, _ := json.Marshal(native[k])
							var attrs map[string]any
							_ = json.Unmarshal(encoded, &attrs)
							for key, value := range v.(map[string]any) {
								if value == nil {
									delete(attrs, key)
								} else {
									attrs[key] = value
								}
							}
							native[k] = attrs
							continue
						}
						native[k] = v
					}
					f.clientWrites++
					if f.lostAck {
						lostHTTPAcknowledgement(w)
						return
					}
					w.WriteHeader(204)
					return
				}
			}
			w.WriteHeader(404)
			return
		}
		if r.Method == http.MethodDelete {
			f.mu.Lock()
			defer f.mu.Unlock()
			for i, native := range f.dependents {
				if r.URL.Path == "/admin/realms/managed/clients/"+native["id"].(string) {
					f.dependents = append(f.dependents[:i], f.dependents[i+1:]...)
					f.nativeDeletes++
					if f.lostAck {
						lostHTTPAcknowledgement(w)
						return
					}
					w.WriteHeader(204)
					return
				}
			}
			w.WriteHeader(404)
			return
		}
		previous.ServeHTTP(w, r)
	})
	return f
}
func lostHTTPAcknowledgement(w http.ResponseWriter) {
	connection, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = connection.Close()
	}
}
func (f *authenticationFixture) runAuthentication(n int) {
	f.t.Helper()
	for range n {
		if _, err := f.reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.account)}); err != nil {
			f.t.Fatal(err)
		}
		if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.account), f.account); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := f.kube.Get(context.Background(), client.ObjectKeyFromObject(f.runtime), f.runtime); err != nil {
		f.t.Fatal(err)
	}
	b, _ := json.Marshal(f.account)
	if f.secret != "" && strings.Contains(string(b), f.secret) || strings.Contains(string(b), "eyJ") {
		f.t.Fatal("credential entered public identity")
	}
}
func (f *authenticationFixture) journal() *workloadauth.Journal {
	f.t.Helper()
	j, err := workloadauth.ParseJournal(f.account.Annotations[workloadauth.JournalKey])
	if err != nil || j == nil {
		f.t.Fatal("no closed authentication journal", err)
	}
	return j
}
func (f *authenticationFixture) approve() {
	f.t.Helper()
	j := f.journal()
	a := workloadauth.Approval{Strategy: "CoordinatedCutover", OwnerUID: j.OwnerUID, Generation: j.Generation, RequestID: j.RequestID, ExpectedClientUUID: j.ClientUUID, ReviewedStateHash: j.NativeStateHash, BindingRevision: j.BindingRevision, PreparedWorkloadRevision: j.PreparedWorkloadRevision, PreviousMode: j.PreviousMode, DesiredMode: j.DesiredMode, TrustUID: j.TrustUID, ProviderID: j.ProviderID, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash, PreparationApproved: true}
	f.account.Annotations[workloadauth.ApprovalKey] = workloadauth.Encode(a)
	if err := f.kube.Update(context.Background(), f.account); err != nil {
		f.t.Fatal(err)
	}
}
func (f *authenticationFixture) review(cleanup bool) {
	f.t.Helper()
	j := f.journal()
	review := workloadauth.Review{RequestID: j.RequestID, ClientUUID: j.ClientUUID, BindingRevision: j.BindingRevision, WorkloadUID: j.WorkloadUID, PlanHash: j.PlanHash}
	f.account.Annotations[workloadauth.ReviewKey] = workloadauth.Encode(review)
	if cleanup {
		var secret corev1.Secret
		if err := f.kube.Get(context.Background(), client.ObjectKey{Namespace: f.account.Namespace, Name: saSecretName(f.account.Spec.ClientID)}, &secret); err != nil {
			f.t.Fatal(err)
		}
		f.account.Annotations[workloadauth.CleanupKey] = workloadauth.Encode(workloadauth.Cleanup{Review: review, SecretUID: string(secret.UID)})
	}
	if err := f.kube.Update(context.Background(), f.account); err != nil {
		f.t.Fatal(err)
	}
}
func (f *authenticationFixture) seedSecretClient() {
	f.t.Helper()
	f.nativeClient(string(f.account.UID))
	native := f.dependents[0]
	native["clientAuthenticatorType"] = "client-secret"
	native["attributes"] = map[string]string{"hanko.sh/client-owner-kind": "HankoServiceAccount", "hanko.sh/client-owner-uid": string(f.account.UID), "locale": "fr"}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: f.account.Namespace, Name: saSecretName(f.account.Spec.ClientID), UID: "canonical-uid", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(f.account, api.GroupVersion.WithKind("HankoServiceAccount"))}}, Data: map[string][]byte{"client_secret": []byte(f.secret), "unrelated": []byte("preserved")}}
	if err := f.kube.Create(context.Background(), secret); err != nil {
		f.t.Fatal(err)
	}
}
func (f *authenticationFixture) requestTransition(id, mode string) {
	f.t.Helper()
	auth := f.account.Spec.Authentication
	if mode == "Secret" {
		auth.FallbackBinding = auth.Kubernetes
		auth.Kubernetes = nil
	} else if auth.Kubernetes == nil {
		auth.Kubernetes = auth.FallbackBinding
		auth.FallbackBinding = nil
	}
	auth.Mode = mode
	auth.Transition = &api.ServiceAccountAuthenticationTransition{Strategy: "CoordinatedCutover", RequestID: id, PreparedWorkloadRevision: "workload-revision"}
	f.account.Generation++
	for _, key := range []string{workloadauth.ApprovalKey, workloadauth.ReviewKey, workloadauth.CleanupKey} {
		delete(f.account.Annotations, key)
	}
	if mode == "Secret" {
		f.account.Spec.RuntimeMetadata = nil
	}
	if err := f.kube.Update(context.Background(), f.account); err != nil {
		f.t.Fatal(err)
	}
}

func TestFreshFederatedAuthenticationRequiresBindingAndRecoversCreateAcknowledgement(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "lost"}[lost], func(t *testing.T) {
			f := newAuthenticationFixture(t)
			f.lostAck = lost
			f.runAuthentication(1)
			if f.creates != 0 || f.account.Status.Phase != "Pending" || !currentWorkloadCondition(f.account, "WorkloadBindingReady") {
				t.Fatal("native CREATE preceded current binding")
			}
			f.runAuthentication(3)
			if f.account.Status.Phase != "Ready" {
				t.Fatalf("activation not ready: %s", conditionReason(f.account.Status.Conditions, "Synced"))
			}
			if f.creates != 1 || f.switches != 0 || f.rotations != 0 || f.credentialRoutes != 0 || f.account.Status.SecretRef != nil || f.account.Status.LastRotated != nil || f.account.Status.NextRotation != nil || f.journal().Step != "Committed" {
				t.Fatal("fresh activation crossed credential or retry boundary")
			}
			if _, err := f.r.requireActiveWorkloadBinding(context.Background(), f.account); err != nil {
				t.Fatal(err)
			}
			var document workloadbinding.Document
			if json.Unmarshal([]byte(f.runtime.Data[workloadbinding.MetadataKey]), &document) != nil || document.AuthenticationActivation != "Federated" {
				t.Fatal("active metadata is incorrect")
			}
		})
	}
}

func TestReviewedAuthenticationCutoverRetainsSecretUntilExactExternalReviewAndCleanup(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.seedSecretClient()
	f.runAuthentication(2)
	if f.switches != 0 || conditionReason(f.account.Status.Conditions, "Synced") != "AuthenticationApprovalRequired" {
		t.Fatal("ordinary mode edit authorized cutover")
	}
	f.requestTransition("cutover-one", "Kubernetes")
	f.runAuthentication(3)
	if f.switches != 0 || f.journal().Step != "Prepared" {
		t.Fatal("unapproved cutover changed native method")
	}
	f.approve()
	f.lostAck = true
	f.runAuthentication(2)
	if f.switches != 1 || f.journal().Step != "ModeApplied" || conditionReason(f.account.Status.Conditions, "Synced") != "AuthenticationReviewRequired" {
		t.Fatal("lost ACK or absent external review repeated method switch")
	}
	f.review(false)
	f.runAuthentication(2)
	if f.journal().Step != "AuthReviewed" || conditionReason(f.account.Status.Conditions, "Synced") != "AuthenticationCleanupApprovalRequired" {
		t.Fatal("review alone authorized cleanup")
	}
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: f.account.Namespace, Name: saSecretName(f.account.Spec.ClientID)}
	if f.kube.Get(context.Background(), key, &secret) != nil || string(secret.Data["client_secret"]) != f.secret {
		t.Fatal("credential removed without explicit cleanup")
	}
	f.review(true)
	f.runAuthentication(3)
	if f.journal().Step != "Committed" || f.account.Status.Phase != "Ready" || f.switches != 1 || f.rotations != 0 || f.credentialRoutes != 0 {
		t.Fatalf("reviewed cutover did not converge: %s", conditionReason(f.account.Status.Conditions, "Synced"))
	}
	if f.kube.Get(context.Background(), key, &secret) != nil || len(secret.Data["client_secret"]) != 0 || string(secret.Data["unrelated"]) != "preserved" {
		t.Fatal("cleanup did not preserve unrelated fields")
	}
}

func TestFallbackStagesSameSecretBeforeApprovalAndReturnsToFederation(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.seedSecretClient()
	id := f.dependents[0]["id"]
	f.requestTransition("federation-one", "Kubernetes")
	f.runAuthentication(3)
	f.approve()
	f.runAuthentication(1)
	f.review(true)
	f.runAuthentication(2)
	if f.account.Status.Phase != "Ready" {
		t.Fatal("initial federation failed")
	}
	f.requestTransition("fallback-one", "Secret")
	f.denyRecovery = true
	f.runAuthentication(2)
	if f.switches != 1 || f.dependents[0]["clientAuthenticatorType"] != "federated-jwt" || conditionReason(f.account.Status.Conditions, "Synced") != "FallbackSecretUnavailable" {
		t.Fatal("failed recovery changed working authenticator")
	}
	f.denyRecovery = false
	f.runAuthentication(2)
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: f.account.Namespace, Name: saSecretName(f.account.Spec.ClientID)}
	if f.kube.Get(context.Background(), key, &secret) != nil || canonicalServiceAccountSecret(&secret) != f.secret || f.switches != 1 || conditionReason(f.account.Status.Conditions, "Synced") != "AuthenticationApprovalRequired" {
		t.Fatal("fallback did not stage same secret before switch approval")
	}
	f.approve()
	f.lostAck = true
	f.runAuthentication(3)
	if f.journal().Step != "Committed" || f.account.Status.Phase != "Ready" || f.dependents[0]["clientAuthenticatorType"] != "client-secret" || f.switches != 2 || f.rotations != 0 || f.dependents[0]["id"] != id {
		t.Fatalf("fallback did not converge: %s", conditionReason(f.account.Status.Conditions, "Synced"))
	}
	f.requestTransition("federation-two", "Kubernetes")
	f.runAuthentication(3)
	f.approve()
	f.runAuthentication(1)
	f.review(true)
	f.runAuthentication(3)
	if f.account.Status.Phase != "Ready" || f.switches != 3 || f.rotations != 0 || f.dependents[0]["id"] != id || f.journal().Step != "Committed" {
		t.Fatal("return to federation skipped complete transaction")
	}
}

func TestFederatedTransactionResumesAcrossEveryCheckpointFailure(t *testing.T) {
	for _, step := range []string{"Prepared", "ModeApplied", "AuthReviewed", "OutputsCleaned", "Committed"} {
		for _, ackLost := range []bool{false, true} {
			t.Run(step+map[bool]string{false: "-write-refused", true: "-ack-lost"}[ackLost], func(t *testing.T) {
				f := newAuthenticationFixture(t)
				f.seedSecretClient()
				f.requestTransition("cutover", "Kubernetes")
				original := f.kube
				failed := false
				restarted := false
				f.reconciler.Client = interceptor.NewClient(original.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, o client.Object, p client.Patch, opts ...client.PatchOption) error {
					if a, ok := o.(*api.HankoServiceAccount); ok && !failed {
						j, e := workloadauth.ParseJournal(a.Annotations[workloadauth.JournalKey])
						if e == nil && j != nil && j.Step == step {
							failed = true
							if ackLost {
								if err := c.Patch(ctx, o, p, opts...); err != nil {
									return err
								}
							}
							return workloadauth.ErrPrecondition
						}
					}
					return c.Patch(ctx, o, p, opts...)
				}})
				run := func(n int) {
					for range n {
						f.runAuthentication(1)
						if failed && !restarted {
							restarted = true
							f.reconciler = &HankoServiceAccountReconciler{Client: original, APIReader: original, OwnershipReader: original, RuntimeClient: original, WorkloadTrust: f.r, Scheme: original.Scheme()}
							f.account.Status = api.HankoServiceAccountStatus{}
							if err := original.Status().Update(context.Background(), f.account); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
				run(5)
				f.approve()
				run(4)
				f.review(true)
				run(5)
				// Reconstruct the manager and discard status: only provider and durable
				// journal checkpoints may recover an accepted native method write.
				f.reconciler = &HankoServiceAccountReconciler{Client: original, APIReader: original, OwnershipReader: original, RuntimeClient: original, WorkloadTrust: f.r, Scheme: original.Scheme()}
				f.account.Status = api.HankoServiceAccountStatus{}
				if err := original.Status().Update(context.Background(), f.account); err != nil {
					t.Fatal(err)
				}
				f.runAuthentication(4)
				if !failed || f.switches != 1 || f.rotations != 0 || f.account.Status.Phase != "Ready" || f.journal().Step != "Committed" {
					t.Fatalf("checkpoint recovery failed at %s (%s)", step, conditionReason(f.account.Status.Conditions, "Synced"))
				}
			})
		}
	}
}

func TestFederatedApprovalDriftNeverAuthorizesSwitchOrCleanup(t *testing.T) {
	for _, field := range []string{"client", "owner", "generation", "binding", "request", "trust", "provider", "workload", "plan", "prepared", "method", "preparation"} {
		t.Run(field, func(t *testing.T) {
			f := newAuthenticationFixture(t)
			f.seedSecretClient()
			f.requestTransition("cutover", "Kubernetes")
			f.runAuthentication(3)
			f.approve()
			var approval workloadauth.Approval
			if workloadauth.Decode(f.account.Annotations[workloadauth.ApprovalKey], &approval) != nil {
				t.Fatal("approval decode")
			}
			switch field {
			case "client":
				approval.ExpectedClientUUID = "foreign"
			case "owner":
				approval.OwnerUID = "foreign"
			case "generation":
				approval.Generation++
			case "binding":
				approval.BindingRevision = workloadauth.Hash("foreign", 1)
			case "request":
				approval.RequestID = "foreign"
			case "trust":
				approval.TrustUID = "foreign"
			case "provider":
				approval.ProviderID = "foreign"
			case "workload":
				approval.WorkloadUID = "foreign"
			case "plan":
				approval.PlanHash = workloadauth.Hash("foreign", 1)
			case "prepared":
				approval.PreparedWorkloadRevision = "foreign"
			case "method":
				approval.PreviousMode = "Kubernetes"
			case "preparation":
				approval.PreparationApproved = false
			}
			f.account.Annotations[workloadauth.ApprovalKey] = workloadauth.Encode(approval)
			if err := f.kube.Update(context.Background(), f.account); err != nil {
				t.Fatal(err)
			}
			f.runAuthentication(2)
			if f.switches != 0 || conditionReason(f.account.Status.Conditions, "Synced") != "AuthenticationApprovalRequired" {
				t.Fatal("stale approval authorized a method change")
			}
		})
	}
}
