package controller

import (
	"context"
	"errors"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	errNoAdoptionSource = errors.New("no adoption observation source selected")
	errAdoptionIdentity = errors.New("current adoption source identity cannot be verified")
)

func resolveAdoptionSource(ctx context.Context, reader client.Reader, target client.Object) (*api.HankoKeycloakInstance, error) {
	approval, err := adoption.ParseApproval(target.GetAnnotations())
	if err != nil {
		return nil, err
	}
	sourceName := approval.Source
	if importName := target.GetLabels()[importedByLabel]; importName != "" {
		var operation api.HankoImport
		if reader.Get(ctx, types.NamespacedName{Namespace: target.GetNamespace(), Name: importName}, &operation) != nil || operation.Spec.SourceRef == "" || !operation.DeletionTimestamp.IsZero() {
			return nil, errAdoptionIdentity
		}
		if sourceName != "" && sourceName != operation.Spec.SourceRef {
			return nil, errAdoptionIdentity
		}
		sourceName = operation.Spec.SourceRef
	}
	if sourceName == "" {
		return nil, errNoAdoptionSource
	}
	var source api.HankoKeycloakInstance
	if reader.Get(ctx, types.NamespacedName{Namespace: target.GetNamespace(), Name: sourceName}, &source) != nil || !source.DeletionTimestamp.IsZero() || source.UID == "" {
		return nil, errAdoptionIdentity
	}
	return &source, nil
}

func incompleteTargetCandidate(object client.Object) *api.AdoptionCandidateStatus {
	target := adoption.TargetIdentity{Kind: adoptionTargetKind(object), Namespace: object.GetNamespace(), Name: object.GetName(), UID: string(object.GetUID()), Generation: object.GetGeneration(), ImportRef: object.GetLabels()[importedByLabel], TenantRef: object.GetLabels()["hanko.sh/tenant"]}
	return candidateStatus(adoption.Build(target, adoption.ProviderIdentity{}, adoption.Observation{Complete: false, Findings: []adoption.Finding{{Code: "current_inventory_unreadable", Domain: "identity", Message: "current source and target identity could not be verified", Blocking: true}}}, nil))
}

func adoptionTargetKind(object client.Object) string {
	switch object.(type) {
	case *api.HankoApplication:
		return "HankoApplication"
	case *api.HankoRole:
		return "HankoRole"
	case *api.HankoServiceAccount:
		return "HankoServiceAccount"
	case *api.HankoResourceServer:
		return "HankoResourceServer"
	}
	return ""
}
