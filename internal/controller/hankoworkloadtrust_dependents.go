package controller

import (
	"context"
	"slices"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type workloadDependentOwner struct {
	Name, UID, Realm, ClientID string
	Generation                 int64
}

// Classification diagnoses public ownership metadata against current local
// identities. It grants no binding, client mutation or deletion authority:
// every dependent, including disabled and owned clients, blocks trust deletion.
func (r *HankoWorkloadTrustReconciler) workloadDependentOwners(ctx context.Context, s *workloadSnapshot) (api.WorkloadTrustDependents, string, error) {
	owners := []workloadDependentOwner{}
	continuation := ""
	seen := map[string]bool{}
	count := 0
	for {
		var page api.HankoServiceAccountList
		if r.APIReader.List(ctx, &page, client.InNamespace(s.trust.Namespace), client.Limit(100), client.Continue(continuation)) != nil || len(page.Items) > 1024-count {
			return api.WorkloadTrustDependents{}, "", trustFailure("IncompleteProviderRead")
		}
		count += len(page.Items)
		for _, a := range page.Items {
			if a.Spec.RealmRef == s.trust.Spec.RealmRef {
				owners = append(owners, workloadDependentOwner{a.Name, string(a.UID), a.Spec.RealmRef, a.Spec.ClientID, a.Generation})
			}
		}
		if page.Continue == "" {
			break
		}
		if seen[page.Continue] {
			return api.WorkloadTrustDependents{}, "", trustFailure("IncompleteProviderRead")
		}
		seen[page.Continue] = true
		continuation = page.Continue
	}
	slices.SortFunc(owners, func(a, b workloadDependentOwner) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	var counts api.WorkloadTrustDependents
	for _, d := range s.dependencies {
		if d.Authenticator != "federated-jwt" || d.Issuer != s.trust.Spec.KeycloakAlias {
			continue
		}
		switch classifyWorkloadDependent(d, owners) {
		case "owned":
			counts.Owned++
		case "foreign":
			counts.Foreign++
		default:
			counts.Ambiguous++
		}
	}
	return counts, workloadtrust.Digest("dependent-local-owners", owners), nil
}

func classifyWorkloadDependent(d keycloak.DependentClient, owners []workloadDependentOwner) string {
	claims := 0
	match := false
	for _, owner := range owners {
		if owner.ClientID == d.ClientID {
			claims++
			match = owner.UID != "" && owner.UID == d.OwnerUID
		}
	}
	if claims > 1 || (d.OwnerKind == "") != (d.OwnerUID == "") || d.OwnerUID != "" && !workloadtrust.ValidOwner(d.OwnerUID) {
		return "ambiguous"
	}
	if d.OwnerKind == "HankoServiceAccount" && claims == 1 && match {
		return "owned"
	}
	if claims > 0 || d.OwnerKind != "" && d.OwnerKind != "HankoServiceAccount" && d.OwnerKind != "HankoApplication" {
		return "ambiguous"
	}
	return "foreign"
}
