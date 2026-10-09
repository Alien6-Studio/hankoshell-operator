package controller

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"unicode"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	maxOrganizationInventory   = 1024
	maxOrganizationDepth       = 32
	organizationPrincipalIndex = "hanko.sh/resource-server-organization-principals"
)

type organizationGrantResolver struct {
	reader           client.Reader
	provider         authorization.OrganizationGroupReader
	namespace, realm string
	graph            map[string]*api.HankoOrganization
	fingerprint      iamcontract.Digest
	verified         map[string]authorization.OrganizationGroup
}

// load reads a complete bounded namespace inventory. Its fingerprint captures
// additions/deletions and status/provider selection changes, not only root generation.
func (r *organizationGrantResolver) load(ctx context.Context) error {
	if r.graph != nil {
		return nil
	}
	var list api.HankoOrganizationList
	if err := r.reader.List(ctx, &list, client.InNamespace(r.namespace), client.Limit(maxOrganizationInventory+1)); err != nil {
		return authorization.OrganizationFailure("OrganizationReadUnavailable")
	}
	if list.Continue != "" || len(list.Items) > maxOrganizationInventory {
		return authorization.OrganizationFailure("OrganizationExpansionTooLarge")
	}
	slices.SortFunc(list.Items, func(a, b api.HankoOrganization) int { return strings.Compare(a.Name, b.Name) })
	type identity struct {
		Name, UID, Realm, Parent, ProviderName, GroupID, Path string
		Generation, ObservedGeneration, SyncGeneration        int64
		Synced, Deleting                                      bool
		Labels                                                map[string]string
	}
	identities := []identity{}
	r.graph = map[string]*api.HankoOrganization{}
	r.verified = map[string]authorization.OrganizationGroup{}
	for i := range list.Items {
		o := &list.Items[i]
		if _, exists := r.graph[o.Name]; exists {
			return authorization.OrganizationFailure("OrganizationOwnershipConflict")
		}
		r.graph[o.Name] = o
		synced, syncGeneration := false, int64(0)
		for _, c := range o.Status.Conditions {
			if c.Type == "Synced" {
				synced = c.Status == metav1.ConditionTrue
				syncGeneration = c.ObservedGeneration
			}
		}
		identities = append(identities, identity{o.Name, string(o.UID), o.Spec.RealmRef, o.Spec.ParentRef, o.Spec.Name, o.Status.GroupID, o.Status.GroupPath, o.Generation, o.Status.ObservedGeneration, syncGeneration, synced, !o.DeletionTimestamp.IsZero(), o.Labels})
	}
	data, _ := json.Marshal(identities)
	r.fingerprint = iamcontract.Hash(iamcontract.Version, "organization", "namespace-graph", data)
	return nil
}

func (r *organizationGrantResolver) resolve(ctx context.Context, p api.AuthorizationPrincipal) (authorization.Principal, error) {
	if err := r.load(ctx); err != nil {
		return authorization.Principal{}, err
	}
	root, chain, err := r.verify(ctx, p.Ref, nil)
	if err != nil {
		return authorization.Principal{}, err
	}
	resolved := &authorization.ResolvedOrganizationPrincipal{Groups: []authorization.OrganizationGroup{root}, Ancestors: chain, Graph: r.fingerprint}
	if p.IncludeDescendants {
		names, err := r.descendants(p.Ref)
		if err != nil {
			return authorization.Principal{}, err
		}
		for _, name := range names {
			group, _, err := r.verify(ctx, name, nil)
			if err != nil {
				return authorization.Principal{}, err
			}
			resolved.Groups = append(resolved.Groups, group)
		}
	}
	return authorization.Principal{Kind: "organization", Ref: p.Ref, IncludeDescendants: p.IncludeDescendants, Organization: resolved}, nil
}

func (r *organizationGrantResolver) verify(ctx context.Context, name string, visiting []string) (authorization.OrganizationGroup, []authorization.OrganizationGroup, error) {
	if slices.Contains(visiting, name) {
		return authorization.OrganizationGroup{}, nil, authorization.OrganizationFailure("OrganizationHierarchyCycle")
	}
	if len(visiting) > maxOrganizationDepth {
		return authorization.OrganizationGroup{}, nil, authorization.OrganizationFailure("OrganizationHierarchyTooDeep")
	}
	o, exists := r.graph[name]
	if !exists {
		return authorization.OrganizationGroup{}, nil, authorization.OrganizationFailure("OrganizationNotFound")
	}
	if o.Spec.RealmRef != r.realm {
		return authorization.OrganizationGroup{}, nil, authorization.OrganizationFailure("OrganizationRealmMismatch")
	}
	if !organizationProviderCurrent(o) {
		return authorization.OrganizationGroup{}, nil, authorization.OrganizationFailure("OrganizationNotCurrent")
	}
	if !safeOrganizationSegment(o.Spec.Name) {
		return authorization.OrganizationGroup{}, nil, authorization.OrganizationFailure("OrganizationHierarchyMismatch")
	}
	path := "/" + o.Spec.Name
	ancestors := []authorization.OrganizationGroup{}
	if o.Spec.ParentRef != "" {
		parent, chain, err := r.verify(ctx, o.Spec.ParentRef, append(slices.Clone(visiting), name))
		if err != nil {
			return authorization.OrganizationGroup{}, nil, err
		}
		path = parent.Path + path
		ancestors = append(chain, parent)
	}
	if o.Status.GroupPath != path {
		return authorization.OrganizationGroup{}, nil, authorization.OrganizationFailure("OrganizationHierarchyMismatch")
	}
	if g, ok := r.verified[name]; ok {
		return g, ancestors, nil
	}
	expected := authorization.OrganizationGroup{Ref: o.Name, Namespace: o.Namespace, UID: string(o.UID), ID: o.Status.GroupID, Name: o.Spec.Name, Path: path}
	group, err := r.provider.ReadOrganizationGroup(ctx, r.realm, expected)
	if err != nil {
		return authorization.OrganizationGroup{}, nil, err
	}
	// A reader must return the exact verified identity; it cannot substitute a group.
	if group != expected {
		return authorization.OrganizationGroup{}, nil, authorization.OrganizationFailure("OrganizationOwnershipConflict")
	}
	r.verified[name] = group
	return group, ancestors, nil
}

func organizationProviderCurrent(o *api.HankoOrganization) bool {
	if o.UID == "" || !o.DeletionTimestamp.IsZero() || o.Status.ObservedGeneration != o.Generation || o.Status.GroupID == "" || o.Status.GroupPath == "" {
		return false
	}
	for _, c := range o.Status.Conditions {
		if c.Type == "Synced" {
			return c.Status == metav1.ConditionTrue && c.ObservedGeneration == o.Generation
		}
	}
	return false
}

func safeOrganizationSegment(s string) bool {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\%") {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

func (r *organizationGrantResolver) descendants(root string) ([]string, error) {
	names := []string{}
	var walk func(string, []string) error
	walk = func(parent string, visiting []string) error {
		if slices.Contains(visiting, parent) {
			return authorization.OrganizationFailure("OrganizationHierarchyCycle")
		}
		if len(visiting) > maxOrganizationDepth {
			return authorization.OrganizationFailure("OrganizationHierarchyTooDeep")
		}
		children := []string{}
		for name, o := range r.graph {
			if o.Spec.ParentRef == parent {
				children = append(children, name)
			}
		}
		slices.Sort(children)
		for _, name := range children {
			names = append(names, name)
			if len(names)+1 > 128 {
				return authorization.OrganizationFailure("OrganizationExpansionTooLarge")
			}
			if err := walk(name, append(slices.Clone(visiting), parent)); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk(root, nil)
	return names, err
}

func (r *HankoResourceServerReconciler) authorityReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func organizationPrincipalIndexValues(object client.Object) []string {
	rs, ok := object.(*api.HankoResourceServer)
	if !ok {
		return nil
	}
	for _, p := range rs.Spec.Permissions {
		for _, v := range p.Principals {
			if v.Kind == "organization" {
				return []string{"true"}
			}
		}
	}
	return nil
}

// Any organization status/spec/create/delete change requeues namespace-local
// organizational grants, including previously unknown descendants. The index
// excludes all ResourceServers without this explicit principal capability.
func (r *HankoResourceServerReconciler) organizationRequests(ctx context.Context, object client.Object) []reconcile.Request {
	var list api.HankoResourceServerList
	err := r.List(ctx, &list, client.InNamespace(object.GetNamespace()), client.MatchingFields{organizationPrincipalIndex: "true"}, client.Limit(maxOrganizationInventory+1))
	if err != nil || list.Continue != "" || len(list.Items) > maxOrganizationInventory {
		log.FromContext(ctx).Error(authorization.OrganizationFailure("OrganizationExpansionTooLarge"), "organization dependency watch inventory unavailable; periodic reconciliation remains active")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for _, rs := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&rs)})
	}
	return requests
}
