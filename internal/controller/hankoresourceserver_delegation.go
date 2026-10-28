package controller

import (
	"context"
	"errors"
	"slices"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	validation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const delegationReferenceIndex = "hanko.sh/resource-server-delegation-references"

func resourceServerHasDelegation(obj *api.HankoResourceServer) bool {
	for _, p := range obj.Spec.Permissions {
		if p.Delegation != nil {
			return true
		}
	}
	return false
}

func portableDelegation(value *api.AuthorizationDelegation) *authorization.Delegation {
	if value == nil {
		return nil
	}
	d := &authorization.Delegation{
		Actor:             authorization.Principal{Kind: value.Actor.Kind, Ref: value.Actor.Ref},
		Subject:           authorization.Principal{Kind: value.Subject.Kind, Ref: value.Subject.Ref},
		TaskAuthorization: value.TaskAuthorization,
		MaxDepth:          authorization.DefaultDelegationDepth, MaxTTLSeconds: authorization.DefaultDelegationTTLSeconds,
	}
	if value.MaxDepth != nil {
		d.MaxDepth = *value.MaxDepth
	}
	if value.MaxTTLSeconds != nil {
		d.MaxTTLSeconds = *value.MaxTTLSeconds
	}
	return d
}

func validatePortableDelegation(permission api.AuthorizationPermission) error {
	d := portableDelegation(permission.Delegation)
	if d == nil {
		return nil
	}
	if len(permission.Resources) == 0 || d.MaxDepth < 1 || d.MaxDepth > 4 || d.MaxTTLSeconds < 1 || d.MaxTTLSeconds > 600 {
		return errors.New("delegation requires explicit resources, depth 1..4 and lifetime 1..600 seconds")
	}
	if d.TaskAuthorization != "" && (d.TaskAuthorization != "required" || d.MaxDepth != 1) {
		return errors.New("task authorization requires an explicit supported capability and one hop")
	}
	for _, identity := range []authorization.Principal{d.Actor, d.Subject} {
		if (identity.Kind != "application" && identity.Kind != "service_account") || len(validation.IsDNS1123Subdomain(identity.Ref)) > 0 {
			return errors.New("delegation requires namespace-local HankoApplication or HankoServiceAccount references")
		}
	}
	if d.Actor.Kind == d.Subject.Kind && d.Actor.Ref == d.Subject.Ref {
		return errors.New("delegation actor and subject must differ")
	}
	return nil
}

// Check only Kubernetes references before the capability gate. In particular,
// do not run workload activation/cleanup, external ownership or adoption here.
func validateDelegationReferences(ctx context.Context, reader client.Reader, obj *api.HankoResourceServer) error {
	var realm api.HankoRealm
	if err := reader.Get(ctx, client.ObjectKey{Namespace: obj.Namespace, Name: obj.Spec.RealmRef}, &realm); err != nil {
		return err
	}
	if !delegationReferenceCurrent(obj, &realm) {
		return errors.New("delegation realm reference is not current or belongs to another tenant")
	}
	if _, err := readDelegationIdentity(ctx, reader, obj, api.AuthorizationDelegationIdentity{Kind: "application", Ref: obj.Spec.ApplicationRef}); err != nil {
		return err
	}
	for _, permission := range obj.Spec.Permissions {
		for _, principal := range permission.Principals {
			if err := validateDelegationGrantReference(ctx, reader, obj, &realm, principal); err != nil {
				return err
			}
		}
		if permission.Delegation == nil {
			continue
		}
		actor, err := readDelegationIdentity(ctx, reader, obj, permission.Delegation.Actor)
		if err != nil {
			return err
		}
		subject, err := readDelegationIdentity(ctx, reader, obj, permission.Delegation.Subject)
		if err != nil {
			return err
		}
		if actor == subject {
			return errors.New("delegation references resolve to the same provider identity")
		}
	}
	return nil
}

func validateDelegationGrantReference(ctx context.Context, reader client.Reader, obj *api.HankoResourceServer, realm *api.HankoRealm, principal api.AuthorizationPrincipal) error {
	key := client.ObjectKey{Namespace: obj.Namespace, Name: principal.Ref}
	var reference client.Object
	var realmRef string
	switch principal.Kind {
	case "application", "service_account":
		_, err := readDelegationIdentity(ctx, reader, obj, api.AuthorizationDelegationIdentity{Kind: principal.Kind, Ref: principal.Ref})
		return err
	case "realm_role":
		if slices.ContainsFunc(realm.Spec.Roles, func(role api.RealmRole) bool { return role.Name == principal.Ref }) {
			return nil
		}
		role := &api.HankoRole{}
		if err := reader.Get(ctx, key, role); err != nil {
			return err
		}
		reference, realmRef = role, role.Spec.RealmRef
	case "organization":
		organization := &api.HankoOrganization{}
		if err := reader.Get(ctx, key, organization); err != nil {
			return err
		}
		reference, realmRef = organization, organization.Spec.RealmRef
	default:
		return errors.New("unsupported delegation grant principal")
	}
	if !delegationReferenceCurrent(obj, reference) || realmRef != obj.Spec.RealmRef {
		return errors.New("delegation grant reference is stale or outside the realm/tenant")
	}
	return nil
}

func delegationReferenceCurrent(owner *api.HankoResourceServer, ref client.Object) bool {
	return ref.GetUID() != "" && ref.GetNamespace() == owner.Namespace && ref.GetDeletionTimestamp().IsZero() && ref.GetLabels()["hanko.sh/tenant"] == owner.Labels["hanko.sh/tenant"]
}

func readDelegationIdentity(ctx context.Context, reader client.Reader, obj *api.HankoResourceServer, ref api.AuthorizationDelegationIdentity) (string, error) {
	key := client.ObjectKey{Namespace: obj.Namespace, Name: ref.Ref}
	var identity client.Object
	var realm, clientID string
	switch ref.Kind {
	case "application":
		app := &api.HankoApplication{}
		if err := reader.Get(ctx, key, app); err != nil {
			return "", err
		}
		identity, realm, clientID = app, app.Spec.RealmRef, app.Spec.ClientID
		if app.Spec.Protocol != "" && app.Spec.Protocol != "oidc" {
			return "", errors.New("delegation requires OIDC software identities")
		}
	case "service_account":
		account := &api.HankoServiceAccount{}
		if err := reader.Get(ctx, key, account); err != nil {
			return "", err
		}
		identity, realm, clientID = account, account.Spec.RealmRef, account.Spec.ClientID
	default:
		return "", errors.New("unsupported delegation identity kind")
	}
	if !delegationReferenceCurrent(obj, identity) || realm != obj.Spec.RealmRef || strings.TrimSpace(clientID) == "" {
		return "", errors.New("delegation identity reference is unresolved, stale or outside the realm/tenant")
	}
	return clientID, nil
}

func (r *HankoResourceServerReconciler) checkDelegationCapability(ctx context.Context, obj *api.HankoResourceServer, driver authorization.Driver) error {
	if !resourceServerHasDelegation(obj) {
		return nil
	}
	if err := validatePortableAuthorizationSpec(obj.Spec); err != nil {
		return err
	}
	if err := validateDelegationReferences(ctx, r.authorityReader(), obj); err != nil {
		return err
	}
	caps, err := driver.Capabilities(ctx, obj.Spec.RealmRef)
	if err != nil {
		return iamcontract.SafeError(err)
	}
	if !caps.BoundedDelegation {
		return iamEvaluationRejected{cause: authorization.DelegationUnsupported(), authorizationCaps: caps,
			identity: iamcontract.PlanIdentity{Contract: iamcontract.Version, Backend: iamcontract.Keycloak, Intent: authorizationIntent(obj).Identity()}}
	}
	return nil
}

func delegationIndexValues(object client.Object) []string {
	obj, ok := object.(*api.HankoResourceServer)
	if !ok || !resourceServerHasDelegation(obj) {
		return nil
	}
	values := []string{"realm/" + obj.Spec.RealmRef, "application/" + obj.Spec.ApplicationRef}
	for _, p := range obj.Spec.Permissions {
		if p.Delegation != nil {
			values = append(values, p.Delegation.Actor.Kind+"/"+p.Delegation.Actor.Ref, p.Delegation.Subject.Kind+"/"+p.Delegation.Subject.Ref)
		}
	}
	slices.Sort(values)
	return slices.Compact(values)
}

func (r *HankoResourceServerReconciler) delegationRequests(ctx context.Context, object client.Object) []reconcile.Request {
	var kind string
	switch object.(type) {
	case *api.HankoRealm:
		kind = "realm"
	case *api.HankoApplication:
		kind = "application"
	case *api.HankoServiceAccount:
		kind = "service_account"
	default:
		return nil
	}
	var list api.HankoResourceServerList
	if err := r.List(ctx, &list, client.InNamespace(object.GetNamespace()), client.MatchingFields{delegationReferenceIndex: kind + "/" + object.GetName()}, client.Limit(maxOrganizationInventory+1)); err != nil || len(list.Items) > maxOrganizationInventory {
		log.FromContext(ctx).Error(iamcontract.ErrObservationIncomplete, "delegation dependency watch inventory unavailable; periodic reconciliation remains active")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return requests
}
