package controller

import (
	"context"
	"net/url"
	"reflect"
	"slices"
	"strings"

	api "github.com/Alien6-Studio/hankoshell-operator/api/v1alpha1"
	"github.com/Alien6-Studio/hankoshell-operator/internal/adoption"
	"github.com/Alien6-Studio/hankoshell-operator/internal/applications"
	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func observeClientAttributes(item *adoptionInventoryItem, c keycloak.InventoryClient) {
	native, credential := false, false
	for key, value := range c.Attributes {
		switch key {
		case "hanko.sh/application-owner", "hanko.app", "hanko.service", "hanko.sh/resource-server-ownership", "client.secret.creation.time":
		case "post.logout.redirect.uris":
			if safeInventoryURLs(strings.Split(value, "##")) {
				item.fact("postLogoutURIs", setValue(strings.Split(value, "##")))
			} else {
				native = true
				credential = true
			}
		case "pkce.code.challenge.method":
			if value == "S256" || value == "plain" {
				item.fact("attributes", setValue([]string{key + "=" + value}))
			} else {
				native = true
			}
		case "saml.assertion.signature":
			item.fact("signedAssertions", flagValue(value == "true"))
		case "saml.server.signature":
			item.fact("signedResponses", flagValue(value == "true"))
		case "saml_name_id_format":
			if value == "username" {
				value = "unspecified"
			}
			if slices.Contains([]string{"persistent", "transient", "email", "unspecified"}, value) {
				item.fact("nameID", textValue(value))
			} else {
				native = true
			}
		case "saml_assertion_consumer_url_post":
			if safeSAMLACS(value) {
				item.fact("acs", setValue([]string{value}))
			} else {
				native = true
				credential = true
			}
		case "saml.client.signature", "saml.encrypt", "saml.artifact.binding", "saml.allow.ecp.flow":
			if value != "false" {
				native = true
			}
		case "saml.signing.certificate", "saml.encryption.certificate", "saml.signing.private.key":
			credential = true
			native = true
		case "saml.signature.algorithm":
			if value != "RSA_SHA256" {
				native = true
			}
		case "saml.force.post.binding", "saml_force_name_id_format", "saml.authnstatement":
			if value != "true" {
				native = true
			}
		case "saml_signature_canonicalization_method":
			if value != "http://www.w3.org/2001/10/xml-exc-c14n#" {
				native = true
			}
		case "saml.artifact.binding.identifier": // generated identifier, ignored by qualified POST-only mapping
		default:
			native = true
		}
	}
	if native {
		item.native("nativePresence", "undeclared native client attributes present", true)
	}
	item.credential(credential)
}
func observeInventoryMappers(item *adoptionInventoryItem, mappers []keycloak.ProtocolMapper) {
	for _, mapper := range mappers {
		item.ids = append(item.ids, mapper.ID)
		if owner := mapper.Config[applications.OwnerAttribute]; owner != "" {
			if item.mapperOwners == nil {
				item.mapperOwners = map[string]string{}
			}
			item.mapperOwners[mapper.ID] = owner
			marker := inventoryFact("protocol-mapper", mapper.ID, mapper.Name, "owner", textValue("application-marked"))
			marker.Classification = adoption.Conflicting
			item.observation.Facts = append(item.observation.Facts, marker)
		}

		f := inventoryFact("protocol-mapper", mapper.ID, mapper.Name, "mapperType", textValue(mapper.ProtocolMapper))
		switch mapper.ProtocolMapper {
		case "oidc-usermodel-attribute-mapper", "oidc-usermodel-realm-role-mapper":
			if claim, ok := importedTokenClaim(mapper); !ok {
				f.Classification = adoption.Preserved
				f.RoundTrip = adoption.PreservedNative
				item.finding("mapper_mapping_unsupported", "protocol mapper configuration is not qualified for lossless representation", true)
			} else {
				item.observation.Facts = append(item.observation.Facts, inventoryFact("protocol-mapper", mapper.ID, mapper.Name, "mapperClaim", textValue(claim.Claim)),
					inventoryFact("protocol-mapper", mapper.ID, mapper.Name, "mapperFlags", setValue([]string{"access=" + boolDefault(claim.AddToAccessToken), "id=" + boolDefault(claim.AddToIDToken), "userinfo=" + boolDefault(claim.AddToUserInfo), "json=" + claim.JSONType})),
					inventoryFact("protocol-mapper", mapper.ID, mapper.Name, "claimSource", setValue([]string{"attribute=" + claim.UserAttribute, "realmRoles=" + boolText(claim.RealmRoles), "prefix=" + claim.RealmRolePrefix, "multivalued=" + boolText(claim.Multivalued)})))
			}
		default:
			f.Classification = adoption.Preserved
			f.RoundTrip = adoption.PreservedNative
			item.finding("native_mapper_preserved", "unknown or native protocol mappers remain read-only evidence", false)
		}
		item.observation.Facts = append(item.observation.Facts, f)
	}
}
func importedTokenClaim(mapper keycloak.ProtocolMapper) (api.ApplicationTokenClaim, bool) {
	claim := api.ApplicationTokenClaim{Name: importResourceName("", mapper.Name), KeycloakName: mapper.Name, Claim: mapper.Config["claim.name"], JSONType: mapper.Config["jsonType.label"]}
	allowed := map[string]bool{"claim.name": true, "user.attribute": true, "access.token.claim": true, "id.token.claim": true, "userinfo.token.claim": true, "jsonType.label": true, "multivalued": true, "usermodel.realmRoleMapping.rolePrefix": true, "hanko.sh/application-owner": true}
	for k := range mapper.Config {
		if !allowed[k] {
			return claim, false
		}
	}
	switch mapper.ProtocolMapper {
	case "oidc-usermodel-attribute-mapper":
		claim.UserAttribute = mapper.Config["user.attribute"]
		if claim.UserAttribute == "" {
			return claim, false
		}
	case "oidc-usermodel-realm-role-mapper":
		claim.RealmRoles = true
		if mapper.Config["usermodel.realmRoleMapping.rolePrefix"] != "" {
			return claim, false
		}
	default:
		return claim, false
	}
	claim.AddToAccessToken = boolPointer(mapper.Config["access.token.claim"] == "true")
	claim.AddToIDToken = boolPointer(mapper.Config["id.token.claim"] == "true")
	claim.AddToUserInfo = boolPointer(mapper.Config["userinfo.token.claim"] == "true")
	claim.Multivalued = mapper.Config["multivalued"] == "true"
	if claim.JSONType == "" {
		claim.JSONType = "String"
	}
	if len(claim.Name) > 255 || len(claim.Claim) > 255 || len(claim.UserAttribute) > 255 {
		return claim, false
	}
	if !slices.Contains([]string{"String", "long", "int", "boolean", "JSON"}, claim.JSONType) {
		return claim, false
	}
	for _, key := range []string{"access.token.claim", "id.token.claim", "userinfo.token.claim", "multivalued"} {
		if value := mapper.Config[key]; value != "" && value != "true" && value != "false" {
			return claim, false
		}
	}
	return claim, claim.Claim != ""
}
func importedApplicationSpec(realm string, c keycloak.InventoryClient, roles []keycloak.RealmRole, mappers []keycloak.ProtocolMapper) (api.HankoApplicationSpec, bool) {
	spec := api.HankoApplicationSpec{RealmRef: realm, ClientID: c.ClientID, Type: "web", Protocol: "oidc", Mode: ModeObserve, RedirectURIs: c.RedirectURIs}
	if !safeInventoryURLs(c.RedirectURIs) || !safeInventoryURLs(strings.Split(c.Attributes["post.logout.redirect.uris"], "##")) {
		return spec, false
	}
	if c.PublicClient {
		spec.Type = "spa"
	}
	if c.ServiceAccountsEnabled {
		spec.Type = "m2m"
	}
	for _, r := range roles {
		spec.Roles = append(spec.Roles, api.ApplicationRole{Name: r.Name, Description: r.Description})
	}
	slices.SortFunc(spec.Roles, func(a, b api.ApplicationRole) int { return strings.Compare(a.Name, b.Name) })
	if value := c.Attributes["post.logout.redirect.uris"]; value != "" {
		spec.PostLogoutRedirectURIs = strings.Split(value, "##")
	}
	if c.Attributes["pkce.code.challenge.method"] == "S256" || c.Attributes["pkce.code.challenge.method"] == "plain" {
		spec.Attributes = map[string]string{"pkce.code.challenge.method": c.Attributes["pkce.code.challenge.method"]}
	}
	for _, mapper := range mappers {
		if claim, ok := importedTokenClaim(mapper); ok {
			spec.TokenClaims = append(spec.TokenClaims, claim)
		}
	}
	slices.SortFunc(spec.TokenClaims, func(a, b api.ApplicationTokenClaim) int { return strings.Compare(a.Name, b.Name) })
	if c.Protocol == "saml" {
		spec.Protocol = "saml"
		spec.Type = ""
		spec.RedirectURIs = nil
		spec.PostLogoutRedirectURIs = nil
		spec.Attributes = nil
		spec.TokenClaims = nil
		nameID := c.Attributes["saml_name_id_format"]
		if nameID == "username" {
			nameID = "unspecified"
		}
		switch nameID {
		case "persistent", "transient", "email", "unspecified":
		default:
			return spec, false
		}
		acs := c.RedirectURIs
		if len(acs) == 0 && c.Attributes["saml_assertion_consumer_url_post"] != "" {
			acs = []string{c.Attributes["saml_assertion_consumer_url_post"]}
		}
		spec.SAML = &api.ApplicationSAML{AssertionConsumerServices: acs, RequireSignedAssertions: boolPointer(true), NameIDFormat: nameID}
		if len(acs) == 0 || len(acs) > 8 || c.Attributes["saml.server.signature"] != "true" || c.Attributes["saml.assertion.signature"] != "true" {
			return spec, false
		}
		for _, endpoint := range acs {
			if !safeSAMLACS(endpoint) {
				return spec, false
			}
		}
	} else if c.Protocol != "openid-connect" && c.Protocol != "" {
		return spec, false
	}
	return spec, true
}
func safeSAMLACS(value string) bool { // same qualified URL contract as the adapter
	return len(value) <= adoption.MaxTextBytes && applications.ValidACS(value)
}
func (r *HankoImportReconciler) currentInventoryTarget(ctx context.Context, operation *api.HankoImport, item *adoptionInventoryItem) (adoption.TargetIdentity, []adoption.Fact) {
	target := adoption.TargetIdentity{Namespace: operation.Namespace, Name: importResourceName(item.realm, item.name)}
	var obj client.Object
	switch item.kind {
	case "application":
		var list api.HankoApplicationList
		if r.importReader().List(ctx, &list, client.InNamespace(operation.Namespace)) != nil {
			item.failed("target_read_failed")
			return target, nil
		}
		for i := range list.Items {
			o := &list.Items[i]
			if o.Spec.RealmRef == item.realm && o.Spec.ClientID == item.name {
				if obj != nil {
					item.failed("target_ambiguous")
					return target, nil
				}
				obj = o
			}
		}
		target.Kind = "HankoApplication"
	case "service-account":
		var apps api.HankoApplicationList
		if r.importReader().List(ctx, &apps, client.InNamespace(operation.Namespace)) != nil {
			item.failed("target_read_failed")
			return target, nil
		}
		for i := range apps.Items {
			o := &apps.Items[i]
			if o.Spec.RealmRef == item.realm && o.Spec.ClientID == item.name {
				if obj != nil {
					item.failed("target_ambiguous")
					return target, nil
				}
				obj = o
				target.Kind = "HankoApplication"
			}
		}
		var list api.HankoServiceAccountList
		if r.importReader().List(ctx, &list, client.InNamespace(operation.Namespace)) != nil {
			item.failed("target_read_failed")
			return target, nil
		}
		for i := range list.Items {
			o := &list.Items[i]
			if o.Spec.RealmRef == item.realm && o.Spec.ClientID == item.name {
				if obj != nil {
					item.failed("target_ambiguous")
					return target, nil
				}
				obj = o
			}
		}
		if target.Kind == "" {
			target.Kind = "HankoServiceAccount"
		}
	case "role":
		var list api.HankoRoleList
		if r.importReader().List(ctx, &list, client.InNamespace(operation.Namespace)) != nil {
			item.failed("target_read_failed")
			return target, nil
		}
		for i := range list.Items {
			o := &list.Items[i]
			if o.Spec.RealmRef == item.realm && o.Spec.Name == item.name {
				if obj != nil {
					item.failed("target_ambiguous")
					return target, nil
				}
				obj = o
			}
		}
		target.Kind = "HankoRole"
	case "resource-server":
		var apps api.HankoApplicationList
		if r.importReader().List(ctx, &apps, client.InNamespace(operation.Namespace)) != nil {
			item.failed("target_read_failed")
			return target, nil
		}
		appNames := map[string]bool{}
		for _, app := range apps.Items {
			if app.Spec.RealmRef == item.realm && app.Spec.ClientID == item.name {
				appNames[app.Name] = true
			}
		}
		var list api.HankoResourceServerList
		if r.importReader().List(ctx, &list, client.InNamespace(operation.Namespace)) != nil {
			item.failed("target_read_failed")
			return target, nil
		}
		for i := range list.Items {
			o := &list.Items[i]
			if o.Spec.RealmRef == item.realm && appNames[o.Spec.ApplicationRef] {
				if obj != nil {
					item.failed("target_ambiguous")
					return target, nil
				}
				obj = o
			}
		}
		target.Kind = "HankoResourceServer"
	default:
		return target, nil
	}
	if obj == nil {
		return target, nil
	}
	// Get again using the direct reader: cached list/status cannot supply an UID or spec.
	if err := r.importReader().Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
		item.failed("target_read_failed")
		return target, nil
	}
	target.Name = obj.GetName()
	target.UID = string(obj.GetUID())
	target.Generation = obj.GetGeneration()
	target.ImportRef = obj.GetLabels()[importedByLabel]
	target.TenantRef = obj.GetLabels()["hanko.sh/tenant"]
	if item.ownerID != "" {
		for i, f := range item.observation.Facts {
			if f.Field == "owner" && f.Identity == item.id {
				if f.Value.Text == "unknown-owner" {
					continue
				}
				if item.ownerID == target.UID && (target.Kind == "HankoApplication" || target.Kind == "HankoRole") {
					item.observation.Facts[i].Value = textValue("owned")
					item.observation.Facts[i].Classification = adoption.Supported
				} else {
					item.observation.Facts[i].Classification = adoption.Conflicting
					item.observation.Facts[i].Value = textValue("foreign")
				}
			}
		}
	}

	for i, fact := range item.observation.Facts {
		if fact.Domain != "protocol-mapper" || fact.Field != "owner" {
			continue
		}
		if item.mapperOwners[fact.Identity] == target.UID && target.Kind == "HankoApplication" {
			item.observation.Facts[i].Classification = adoption.Supported
			item.observation.Facts[i].Value = textValue("owned")
		} else {
			item.observation.Facts[i].Classification = adoption.Conflicting
			item.observation.Facts[i].Value = textValue("foreign")
		}
	}
	desired := desiredInventoryFacts(item, obj)
	return target, desired
}
func desiredInventoryFacts(item *adoptionInventoryItem, obj client.Object) []adoption.Fact {
	facts := []adoption.Fact{}
	add := func(field string, value adoption.Value) {
		if slices.Contains([]string{"redirectURIs", "postLogoutURIs", "acs", "webOrigins"}, field) && !safeInventoryURLs(value.Set) {
			item.finding("desired_url_excluded", "credential-bearing or unqualified desired URL is excluded from public evidence", true)
			return
		}
		facts = append(facts, inventoryFact(item.kind, item.id, item.name, field, value))
	}
	add("importLatch", flagValue(isImported(obj.GetLabels())))
	switch o := obj.(type) {
	case *api.HankoApplication:
		add("realmRef", textValue(o.Spec.RealmRef))
		add("mode", textValue(o.Spec.Mode))
		protocol := o.Spec.Protocol
		if protocol == "" || protocol == "oidc" {
			protocol = "openid-connect"
		}
		add("protocol", textValue(protocol))
		add("name", textValue(o.Spec.ClientID))
		add("redirectURIs", setValue(o.Spec.RedirectURIs))
		add("postLogoutURIs", setValue(o.Spec.PostLogoutRedirectURIs))
		add("pattern", textValue(o.Spec.Type))
		add("enabled", flagValue(true))
		add("publicClient", flagValue(o.Spec.Type == "spa"))
		add("standardFlow", flagValue(o.Spec.Type != "m2m"))
		add("serviceAccounts", flagValue(o.Spec.Type == "m2m"))
		add("directAccessGrants", flagValue(false))
		add("implicitFlow", flagValue(false))
		add("fullScopeAllowed", flagValue(false))
		if o.Spec.RealmRoleScopes != nil {
			add("realmRoles", setValue(o.Spec.RealmRoleScopes))
		}
		if len(o.Spec.IdentityMappings) > 0 {
			item.finding("identity_mapping_selection_deferred", "realm-scoped identity mapper selection requires reviewed broker references", true)
		}
		if o.Spec.SecretRotationPolicy != nil && o.Spec.SecretRotationPolicy.Enabled {
			add("credentialRotation", flagValue(true))
			item.finding("credential_rotation_excluded", "credential rotation is outside discovery and adoption diff", true)
		}
		if len(o.Spec.ClientSecretProjections) > 0 {
			item.finding("credential_projection_excluded", "credential delivery is outside discovery and adoption diff", true)
		}
		add("theme", textValue(o.Spec.Theme))
		if o.Spec.SAML != nil {
			add("acs", setValue(o.Spec.SAML.AssertionConsumerServices))
			add("nameID", textValue(o.Spec.SAML.NameIDFormat))
			add("signedAssertions", flagValue(o.Spec.SAML.RequireSignedAssertions == nil || *o.Spec.SAML.RequireSignedAssertions))
			add("signedResponses", flagValue(true))
			add("webOrigins", setValue(nil))
		} else {
			add("webOrigins", setValue([]string{"+"}))
		}
		if len(o.Spec.RuntimeBindings) > 0 {
			add("runtimeBindings", flagValue(true))
			item.finding("runtime_binding_change_deferred", "adoption inventory does not acquire runtime workload bindings", true)
		}
		desiredMetadata(item, add, o.Spec.Attributes)
		desiredClientRoles(item, &facts, o.Spec.Roles)
		desiredTokenClaims(item, &facts, o.Spec.TokenClaims)
	case *api.HankoServiceAccount:
		add("realmRef", textValue(o.Spec.RealmRef))
		add("name", textValue(o.Spec.ClientID))
		add("scopes", setValue(o.Spec.Scopes))
		desiredMetadata(item, add, o.Spec.Attributes)
		desiredTokenClaims(item, &facts, o.Spec.TokenClaims)
		if o.Spec.SecretRotationPolicy != nil && o.Spec.SecretRotationPolicy.Enabled {
			add("credentialRotation", flagValue(true))
			item.finding("credential_rotation_excluded", "credential rotation is outside discovery and adoption diff", true)
		}
	case *api.HankoRole:
		add("realmRef", textValue(o.Spec.RealmRef))
		add("name", textValue(o.Spec.Name))
		add("description", textValue(o.Spec.Description))
		add("composites", setValue(o.Spec.Composites))
		if len(o.Spec.Attributes) > 0 {
			item.finding("desired_role_attributes_unqualified", "arbitrary desired role attributes require a reviewed typed projection", true)
		}
	case *api.HankoResourceServer:
		add("realmRef", textValue(o.Spec.RealmRef))
		add("mode", textValue(o.Spec.Mode))
		add("name", textValue(o.Spec.Audience))
		add("scopes", setValue(scopeNames(o.Spec.Scopes)))
		add("resources", setValue(resourceNames(o.Spec.Resources)))
		add("policies", setValue(permissionNames(o.Spec.Permissions)))
		item.finding("aggregate_acquisition_deferred", "provider-native graph is not portable aggregate ownership authority", true)
	}
	return facts
}
func desiredMetadata(item *adoptionInventoryItem, add func(string, adoption.Value), attrs map[string]string) {
	for k, v := range attrs {
		if k == "pkce.code.challenge.method" && (v == "S256" || v == "plain") {
			add("attributes", setValue([]string{k + "=" + v}))
		} else {
			item.finding("desired_metadata_unqualified", "desired metadata is outside the typed adoption projection", true)
		}
	}
}
func desiredClientRoles(item *adoptionInventoryItem, facts *[]adoption.Fact, roles []api.ApplicationRole) {
	for _, role := range roles {
		found := false
		for _, f := range item.observation.Facts {
			if f.Domain == "client-role" && f.Object == role.Name && f.Field == "description" {
				f.Value = textValue(role.Description)
				*facts = append(*facts, f)
				found = true
				break
			}
		}
		if !found {
			*facts = append(*facts, inventoryFact("client-role", "", role.Name, "description", textValue(role.Description)))
		}
	}
}
func desiredTokenClaims(item *adoptionInventoryItem, facts *[]adoption.Fact, claims []api.ApplicationTokenClaim) {
	for _, claim := range claims {
		id := ""
		for _, f := range item.observation.Facts {
			if f.Domain == "protocol-mapper" && f.Object == effectiveClaimName(claim) {
				id = f.Identity
				break
			}
		}
		*facts = append(*facts, inventoryFact("protocol-mapper", id, effectiveClaimName(claim), "mapperClaim", textValue(claim.Claim)),
			inventoryFact("protocol-mapper", id, effectiveClaimName(claim), "mapperFlags", setValue([]string{"access=" + boolDefault(claim.AddToAccessToken), "id=" + boolDefault(claim.AddToIDToken), "userinfo=" + boolDefault(claim.AddToUserInfo), "json=" + claim.JSONType})),
			inventoryFact("protocol-mapper", id, effectiveClaimName(claim), "claimSource", setValue([]string{"attribute=" + claim.UserAttribute, "realmRoles=" + boolText(claim.RealmRoles), "prefix=" + claim.RealmRolePrefix, "multivalued=" + boolText(claim.Multivalued)})))
		if claim.Value != nil {
			item.finding("claim_value_excluded", "fixed token claim values are excluded from public adoption evidence", true)
		}
	}
}
func scopeNames(v []api.AuthorizationScope) []string {
	r := []string{}
	for _, x := range v {
		r = append(r, x.Name)
	}
	return r
}
func resourceNames(v []api.AuthorizationResource) []string {
	r := []string{}
	for _, x := range v {
		r = append(r, x.Name)
	}
	return r
}
func permissionNames(v []api.AuthorizationPermission) []string {
	r := []string{}
	for _, x := range v {
		r = append(r, x.Name)
	}
	return r
}
func (r *HankoImportReconciler) patchInventoryCandidate(ctx context.Context, target adoption.TargetIdentity, c adoption.Candidate) bool {
	var object client.Object
	switch target.Kind {
	case "HankoApplication":
		object = &api.HankoApplication{}
	case "HankoServiceAccount":
		object = &api.HankoServiceAccount{}
	case "HankoRole":
		object = &api.HankoRole{}
	case "HankoResourceServer":
		object = &api.HankoResourceServer{}
	default:
		return false
	}
	key := types.NamespacedName{Namespace: target.Namespace, Name: target.Name}
	if r.importReader().Get(ctx, key, object) != nil || (string(object.GetUID()) != target.UID || object.GetGeneration() != target.Generation || object.GetLabels()[importedByLabel] != target.ImportRef || object.GetLabels()["hanko.sh/tenant"] != target.TenantRef) {
		return false
	}
	// Evidence is bound to the exact fresh spec and metadata, not status. Avoid
	// timestamps and semantic no-op writes that would create informer hot loops.
	base, ok := object.DeepCopyObject().(client.Object)
	if !ok {
		return false
	}
	patch := client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})
	status := candidateStatus(c)
	var old *api.AdoptionCandidateStatus
	switch o := object.(type) {
	case *api.HankoApplication:
		old = o.Status.AdoptionCandidate
		o.Status.AdoptionCandidate = status
	case *api.HankoServiceAccount:
		old = o.Status.AdoptionCandidate
		o.Status.AdoptionCandidate = status
	case *api.HankoRole:
		old = o.Status.AdoptionCandidate
		o.Status.AdoptionCandidate = status
	case *api.HankoResourceServer:
		old = o.Status.AdoptionCandidate
		o.Status.AdoptionCandidate = status
	}
	if !reflect.DeepEqual(old, status) {
		return r.Status().Patch(ctx, object, patch) == nil
	}
	return true
}

func effectiveClaimName(claim api.ApplicationTokenClaim) string {
	if claim.KeycloakName != "" {
		return claim.KeycloakName
	}
	return claim.Name
}
func boolDefault(value *bool) string {
	if value == nil || *value {
		return "true"
	}
	return "false"
}
func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func safeInventoryURLs(values []string) bool {
	for _, value := range values {
		if value == "" || value == "+" || value == "*" {
			continue
		}
		endpoint, err := url.Parse(value)
		if err != nil || !endpoint.IsAbs() || len(value) > adoption.MaxTextBytes || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || strings.ContainsAny(value, "\r\n\t ") {
			return false
		}
	}
	return true
}
