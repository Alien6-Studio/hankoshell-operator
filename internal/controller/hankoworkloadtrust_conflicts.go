package controller

import (
	"context"
	"slices"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/workloadtrust"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *HankoWorkloadTrustReconciler) allWorkloadTrusts(ctx context.Context, namespace string) ([]api.HankoWorkloadTrust, error) {
	all := []api.HankoWorkloadTrust{}
	continuation := ""
	seen := map[string]bool{}
	for {
		var page api.HankoWorkloadTrustList
		if err := r.APIReader.List(ctx, &page, client.InNamespace(namespace), client.Limit(100), client.Continue(continuation)); err != nil {
			return nil, trustFailure("IncompleteProviderRead")
		}
		if len(page.Items) > 1024-len(all) {
			return nil, trustFailure("IncompleteProviderRead")
		}
		all = append(all, page.Items...)
		if page.Continue == "" {
			return all, nil
		}
		if seen[page.Continue] {
			return nil, trustFailure("IncompleteProviderRead")
		}
		seen[page.Continue] = true
		continuation = page.Continue
	}
}
func (r *HankoWorkloadTrustReconciler) allWorkloadRealms(ctx context.Context, namespace string) ([]api.HankoRealm, error) {
	all := []api.HankoRealm{}
	continuation := ""
	seen := map[string]bool{}
	for {
		var page api.HankoRealmList
		if err := r.APIReader.List(ctx, &page, client.InNamespace(namespace), client.Limit(100), client.Continue(continuation)); err != nil {
			return nil, trustFailure("IncompleteProviderRead")
		}
		if len(page.Items) > 1024-len(all) {
			return nil, trustFailure("IncompleteProviderRead")
		}
		all = append(all, page.Items...)
		if page.Continue == "" {
			return all, nil
		}
		if seen[page.Continue] {
			return nil, trustFailure("IncompleteProviderRead")
		}
		seen[page.Continue] = true
		continuation = page.Continue
	}
}

func (r *HankoWorkloadTrustReconciler) workloadConflicts(ctx context.Context, s *workloadSnapshot) error {
	trusts, err := r.allWorkloadTrusts(ctx, s.trust.Namespace)
	if err != nil {
		return err
	}
	for _, other := range trusts {
		if other.UID == s.trust.UID {
			continue
		}
		if other.UID == "" {
			return trustFailure("ProviderConflict")
		}
		connection, err := r.workloadConnection(ctx, other.Namespace, other.Spec.SourceRef)
		if err != nil {
			return trustFailure("SourceUnavailable")
		}
		if !sameWorkloadConnection(connection, s.source) {
			if other.Spec.RealmRef == s.trust.Spec.RealmRef {
				return trustFailure("ProviderConflict")
			}
			continue
		}
		realm, err := connection.client.GetRealm(ctx, other.Spec.RealmRef)
		connection.client.CloseIdleConnections()
		if err != nil || realm.ID == "" {
			return trustFailure("SourceUnavailable")
		}
		if realm.ID == s.source.identity.RealmID && (other.Spec.KeycloakAlias == s.trust.Spec.KeycloakAlias || other.Spec.Kubernetes.Issuer == s.trust.Spec.Kubernetes.Issuer) {
			return trustFailure("ProviderConflict")
		}
	}
	realms, err := r.allWorkloadRealms(ctx, s.trust.Namespace)
	if err != nil {
		return err
	}
	for _, realm := range realms {
		if len(realm.Spec.IdentityProviders) == 0 {
			continue
		}
		connection := s.source
		if source := realm.Annotations[adoption.SourceAnnotation]; source != "" && source != s.trust.Spec.SourceRef {
			connection, err = r.workloadConnection(ctx, realm.Namespace, source)
			if err != nil {
				return trustFailure("SourceUnavailable")
			}
		}
		if imported := realm.Labels[importedByLabel]; imported != "" {
			var operation api.HankoImport
			if r.APIReader.Get(ctx, types.NamespacedName{Namespace: realm.Namespace, Name: imported}, &operation) != nil {
				return trustFailure("SourceUnavailable")
			}
			connection, err = r.workloadConnection(ctx, realm.Namespace, operation.Spec.SourceRef)
			if err != nil {
				return trustFailure("SourceUnavailable")
			}
		}
		if !sameWorkloadConnection(connection, s.source) {
			if realm.Name == s.realm.Name {
				return trustFailure("ProviderConflict")
			}
			continue
		}
		observed, err := connection.client.GetRealm(ctx, realm.Name)
		connection.client.CloseIdleConnections()
		if err != nil || observed.ID == "" {
			return trustFailure("SourceUnavailable")
		}
		if observed.ID != s.source.identity.RealmID {
			continue
		}
		for _, provider := range realm.Spec.IdentityProviders {
			if provider.Alias == s.trust.Spec.KeycloakAlias || provider.ProviderID == "kubernetes" && provider.Config["issuer"] == s.trust.Spec.Kubernetes.Issuer {
				return trustFailure("ProviderConflict")
			}
		}
	}
	foreign := []struct {
		ID, Alias, ProviderID, Issuer, Owner string
		Qualified                            bool
	}{}
	for _, p := range s.providers {
		if p.Config.Owner == string(s.trust.UID) && p.Alias != s.trust.Spec.KeycloakAlias {
			return trustFailure("OwnershipConflict")
		}
		if p.ProviderID == "kubernetes" && !p.Qualified {
			return trustFailure("UnsupportedNativeState")
		}
		if p.Alias == s.trust.Spec.KeycloakAlias {
			if p.ProviderID != "kubernetes" {
				return trustFailure("ProviderConflict")
			}
			continue
		}
		if p.Config.Issuer == s.trust.Spec.Kubernetes.Issuer {
			return trustFailure("ProviderConflict")
		}
		// Only public issuer/identity and an ownership classification enter this
		// inventory. Foreign arbitrary marker contents never become evidence.
		issuer := ""
		if workloadtrust.ValidHTTPS(p.Config.Issuer) {
			issuer = p.Config.Issuer
		}
		owner := "foreign"
		if p.Config.Owner == "" {
			owner = "unmarked"
		}
		foreign = append(foreign, struct {
			ID, Alias, ProviderID, Issuer, Owner string
			Qualified                            bool
		}{p.InternalID, p.Alias, p.ProviderID, issuer, owner, p.Qualified})
	}
	slices.SortFunc(foreign, func(a, b struct {
		ID, Alias, ProviderID, Issuer, Owner string
		Qualified                            bool
	}) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	s.foreignInventoryHash = workloadtrust.Digest("foreign-provider-inventory", foreign)
	return nil
}
