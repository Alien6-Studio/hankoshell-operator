package controller

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type referenceIdentity struct {
	Namespace, Name, UID string
	Generation           int64
}
type contractReferenceReader struct {
	client.Client
	references []referenceIdentity
}

func (r *contractReferenceReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if !obj.GetDeletionTimestamp().IsZero() {
		return iamcontract.ErrRejected
	}
	r.references = append(r.references, referenceIdentity{obj.GetNamespace(), obj.GetName(), string(obj.GetUID()), obj.GetGeneration()})
	return nil
}
func (r *contractReferenceReader) digest() iamcontract.Digest {
	slices.SortFunc(r.references, func(a, b referenceIdentity) int {
		return strings.Compare(a.Namespace+"/"+a.Name+"/"+a.UID, b.Namespace+"/"+b.Name+"/"+b.UID)
	})
	data, _ := json.Marshal(r.references)
	return iamcontract.Hash(iamcontract.Version, "local", "references", data)
}
func executionPreconditions(obj client.Object, refs iamcontract.Digest, mode string) iamcontract.Preconditions {
	// Mode/import status and provider-selection labels are local authority, not
	// portable semantics. JSON's sorted map keys make this check deterministic.
	data, _ := json.Marshal(struct {
		Mode   string
		Labels map[string]string
	}{mode, obj.GetLabels()})
	return iamcontract.Preconditions{ResourceUID: string(obj.GetUID()), Generation: obj.GetGeneration(), References: refs, Authority: iamcontract.Hash(iamcontract.Version, "local", "authority", data)}
}
