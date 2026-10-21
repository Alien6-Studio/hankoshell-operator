package controller

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/authorization"
	"github.com/Alien6-Studio/hankoshell-operator/internal/iamcontract"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Explanation errors are evidence gaps only. They never invalidate a proven
// application, induce provider writes, or become execution preconditions.
func (r *HankoResourceServerReconciler) explanationEvidence(ctx context.Context, obj *api.HankoResourceServer, driver authorization.Driver, roleIDs map[string]string) authorization.ExplanationEvidence {
	evidence := authorization.ExplanationEvidence{Complete: true}
	refs := map[string]bool{}
	roles := false
	for _, p := range obj.Spec.Permissions {
		for _, v := range p.Principals {
			if v.Kind == "organization" {
				refs[v.Ref] = refs[v.Ref] || v.IncludeDescendants
			}
			roles = roles || v.Kind == "realm_role"
		}
	}
	if len(refs) == 0 && !roles {
		return evidence
	}
	provider, ok := driver.(authorization.OrganizationGroupReader)
	if !ok {
		evidence.Complete = false
		evidence.Findings = append(evidence.Findings, authorization.ExplanationFinding("ProvenanceReadUnavailable"))
		return evidence
	}
	resolver := &organizationGrantResolver{reader: r.authorityReader(), provider: provider, namespace: obj.Namespace, realm: obj.Spec.RealmRef}
	if err := resolver.load(ctx); err != nil {
		evidence.Complete = false
		evidence.Findings = append(evidence.Findings, authorization.ExplanationFinding("OrganizationProvenanceStale"))
		return evidence
	}
	names := []string{}
	for name, o := range resolver.graph {
		_, requested := refs[name]
		if o.Spec.RealmRef == obj.Spec.RealmRef && (roles || requested) {
			names = append(names, name)
		}
	}
	// Explicit descendants require ancestry for every emitted group, not only roots.
	for ref, descendants := range refs {
		if !descendants {
			continue
		}
		children, err := resolver.descendants(ref)
		if err != nil {
			evidence.Complete = false
			continue
		}
		names = append(names, children...)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	for _, name := range names {
		group, ancestors, err := resolver.verify(ctx, name, nil)
		if err != nil {
			evidence.Complete = false
			code := "OrganizationProvenanceStale"
			var failure authorization.OrganizationError
			if errors.As(err, &failure) && failure.Code == "OrganizationReadUnavailable" {
				code = "ProvenanceReadUnavailable"
			}
			evidence.Findings = append(evidence.Findings, authorization.ExplanationFinding(code))
			continue
		}
		evidence.Organizations = append(evidence.Organizations, authorization.VerifiedOrganization{Group: group, Ancestors: ancestors})
	}
	if len(evidence.Organizations) > 128 {
		evidence.Organizations = evidence.Organizations[:128]
		evidence.Complete = false
		evidence.Findings = append(evidence.Findings, authorization.ExplanationFinding("CompositeClosureIncomplete"))
	}
	if roles && len(names) > 0 {
		reader, ok := driver.(authorization.RoleProvenanceReader)
		declarations, err := r.explanationRoleDeclarations(ctx, obj, resolver, roleIDs)
		if !ok || err != nil {
			evidence.Complete = false
			evidence.Findings = append(evidence.Findings, authorization.ExplanationFinding("ProvenanceReadUnavailable"))
		} else {
			roles, findings := reader.ReadRoleProvenance(ctx, obj.Spec.RealmRef, evidence.Organizations, declarations)
			evidence.Roles = roles
			// Re-read optional provider edges and declarations before claiming a current chain.
			nextDeclarations, readErr := r.explanationRoleDeclarations(ctx, obj, resolver, roleIDs)
			nextRoles, nextFindings := reader.ReadRoleProvenance(ctx, obj.Spec.RealmRef, evidence.Organizations, nextDeclarations)
			a, _ := json.Marshal(struct {
				Roles        []authorization.RoleBinding
				Declarations []authorization.RoleDeclaration
			}{roles, declarations})
			b, _ := json.Marshal(struct {
				Roles        []authorization.RoleBinding
				Declarations []authorization.RoleDeclaration
			}{nextRoles, nextDeclarations})
			if readErr != nil || len(nextFindings) > 0 || string(a) != string(b) {
				evidence.Roles = nil
				evidence.Complete = false
				findings = append(findings, authorization.ExplanationFinding("ProvenanceReadUnavailable"))
			}
			evidence.Findings = append(evidence.Findings, findings...)
			if len(evidence.Findings) > 0 {
				evidence.Complete = false
			}
		}
	}
	// Ownership/hierarchy locators are rechecked after optional role reads.
	for _, v := range evidence.Organizations {
		if actual, err := provider.ReadOrganizationGroup(ctx, obj.Spec.RealmRef, v.Group); err != nil || actual != v.Group {
			evidence.Complete = false
			evidence.Roles = nil
			evidence.Findings = append(evidence.Findings, authorization.ExplanationFinding("OrganizationProvenanceStale"))
		}
	}
	// Detect Kubernetes additions/deletions/spec/status changes across provenance reads.
	fresh := &organizationGrantResolver{reader: r.authorityReader(), namespace: obj.Namespace, realm: obj.Spec.RealmRef}
	if err := fresh.load(ctx); err != nil || fresh.fingerprint != resolver.fingerprint {
		evidence.Complete = false
		evidence.Roles = nil
		evidence.Organizations = nil
		evidence.Findings = append(evidence.Findings, authorization.ExplanationFinding("OrganizationProvenanceStale"))
	}
	return evidence
}

func (r *HankoResourceServerReconciler) explanationRoleDeclarations(ctx context.Context, obj *api.HankoResourceServer, resolver *organizationGrantResolver, roleIDs map[string]string) ([]authorization.RoleDeclaration, error) {
	reader := r.authorityReader()
	result := []authorization.RoleDeclaration{}
	add := func(kind, ref, name, client string) {
		result = append(result, authorization.RoleDeclaration{Kind: kind, Ref: ref, Name: name, Client: client, Target: explanationTarget(obj, kind, ref), ExpectedID: roleIDs[name]})
	}
	var realm api.HankoRealm
	if err := reader.Get(ctx, client.ObjectKey{Namespace: obj.Namespace, Name: obj.Spec.RealmRef}, &realm); err != nil {
		return nil, err
	}
	for _, v := range realm.Spec.Roles {
		add("realm_role", v.Name, v.Name, "")
		for _, n := range v.Composites {
			add("realm_role", n, n, "")
		}
	}
	var roles api.HankoRoleList
	if err := reader.List(ctx, &roles, client.InNamespace(obj.Namespace), client.Limit(maxOrganizationInventory+1)); err != nil {
		return nil, err
	}
	if roles.Continue != "" || len(roles.Items) > maxOrganizationInventory {
		return nil, iamcontract.ErrObservationIncomplete
	}
	roleRefs := map[string]string{}
	for _, v := range roles.Items {
		if v.Spec.RealmRef == obj.Spec.RealmRef {
			roleRefs[v.Spec.Name] = v.Name
		}
	}
	for _, v := range roles.Items {
		if v.Spec.RealmRef == obj.Spec.RealmRef {
			add("realm_role", v.Name, v.Spec.Name, "")
			for _, n := range v.Spec.Composites {
				ref := n
				if roleRefs[n] != "" {
					ref = roleRefs[n]
				}
				add("realm_role", ref, n, "")
			}
		}
	}
	for _, o := range resolver.graph {
		if o.Spec.RealmRef != obj.Spec.RealmRef {
			continue
		}
		for _, name := range o.Spec.Roles {
			ref := name
			if roleRefs[name] != "" {
				ref = roleRefs[name]
			}
			add("realm_role", ref, name, "")
		}
		for _, v := range o.Spec.ClientRoles {
			for _, name := range v.Roles {
				add("client_role", name, name, v.Client)
			}
		}
	}
	slices.SortFunc(result, func(a, b authorization.RoleDeclaration) int {
		aBytes, _ := json.Marshal(a)
		bBytes, _ := json.Marshal(b)
		return strings.Compare(string(aBytes), string(bBytes))
	})
	return slices.Compact(result), nil
}

func (r *HankoResourceServerReconciler) projectExplanation(ctx context.Context, obj *api.HankoResourceServer, state authorization.State, plan authorization.Plan, applied bool) {
	if state.Structure == nil || !iamcontract.ValidDigest(string(state.Observation.StateHash)) {
		historicalExplanation(obj, "NotObserved", metav1.ConditionUnknown)
		return
	}
	optionalCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	evidence := r.explanationEvidence(optionalCtx, obj, r.driverFor(obj), state.RealmRoleIDs)
	explanation := authorization.Explain(plan, state, evidence, obj.Generation, applied)
	// Revalidate mandatory plan dependencies after optional evidence, without
	// weakening or changing the authorization synchronization outcome.
	if err := r.validateAuthorizationExecution(ctx, obj, r.driverFor(obj), plan); err != nil {
		historicalExplanation(obj, "Stale", metav1.ConditionFalse)
		return
	}
	bytes, _ := json.Marshal(explanation)
	var projected api.AuthorizationExplanation
	_ = json.Unmarshal(bytes, &projected)
	obj.Status.AuthorizationExplanation = &projected
	findings := append(slices.Clone(state.Findings), evidence.Findings...)
	reason := "Complete"
	status := metav1.ConditionTrue
	if state.Structure.Native {
		findings = append(findings, authorization.ExplanationFinding("NativeAuthorizationUnexplained"))
	}
	if !explanation.Complete {
		reason = "Incomplete"
		status = metav1.ConditionFalse
		findings = append(findings, authorization.ExplanationFinding("ExplanationIncomplete"))
	}
	if explanation.Truncated {
		reason = "Truncated"
		findings = append(findings, authorization.ExplanationFinding("ExplanationTruncated"))
	}
	for _, f := range evidence.Findings {
		if f.Code == "ProvenanceReadUnavailable" {
			reason = f.Code
		}
		if f.Code == "OrganizationProvenanceStale" {
			reason = "Stale"
		}
	}
	obj.Status.Findings = findingsStatus(findings)
	iamCondition(&obj.Status.Conditions, obj.Generation, "AuthorizationExplained", status, reason, "bounded structural provider evidence; runtime subjects are not evaluated")
}
func historicalExplanation(obj *api.HankoResourceServer, reason string, status metav1.ConditionStatus) {
	if obj.Status.AuthorizationExplanation == nil {
		status = metav1.ConditionUnknown
		reason = "NotObserved"
	}
	if obj.Status.AuthorizationExplanation != nil {
		status = metav1.ConditionFalse
		if reason == "NotObserved" {
			reason = "Stale"
		}
	}
	iamCondition(&obj.Status.Conditions, obj.Generation, "AuthorizationExplained", status, reason, "no current structural explanation is proven; previous evidence may be historical")
}

// Realm-role-only ResourceServers also depend on organization mapping evidence.
func authorizationProvenanceIndexValues(object client.Object) []string {
	obj, ok := object.(*api.HankoResourceServer)
	if !ok {
		return nil
	}
	for _, p := range obj.Spec.Permissions {
		for _, v := range p.Principals {
			if slices.Contains([]string{"organization", "realm_role"}, v.Kind) {
				return []string{"true"}
			}
		}
	}
	return nil
}

func explanationTarget(obj *api.HankoResourceServer, kind, ref string) bool {
	for _, p := range obj.Spec.Permissions {
		for _, v := range p.Principals {
			if v.Kind == kind && v.Ref == ref {
				return true
			}
		}
	}
	return false
}
