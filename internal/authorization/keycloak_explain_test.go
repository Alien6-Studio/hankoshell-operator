package authorization

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Alien6-Studio/hankoshell-operator/internal/keycloak"
)

func TestRoleProvenanceMustMatchObservedPolicyRoleIdentity(t *testing.T) {
	declarations := []RoleDeclaration{{Kind: "realm_role", Ref: "reader", Name: "reader", Target: true, ExpectedID: "observed-role-uuid"}}
	index := indexDeclaredRoles(declarations)
	actual := []keycloak.GroupRolePath{{Roles: []keycloak.RealmRole{{ID: "new-same-name-role-uuid", Name: "reader"}}}}
	bindings, findings := groupRoleBindings("europe", actual, index)
	if len(bindings) != 0 || len(findings) != 1 || findings[0].Code != "RoleProvenanceAmbiguous" {
		t.Fatal("same-name role recreation fabricated a policy/mapping bridge")
	}
	actual[0].Roles[0].ID = "observed-role-uuid"
	bindings, findings = groupRoleBindings("europe", actual, index)
	if len(bindings) != 1 || len(findings) != 0 {
		t.Fatal("exact observed role mapping refused")
	}
	data, _ := json.Marshal(bindings)
	if strings.Contains(string(data), "uuid") {
		t.Fatal("private role locator entered public provenance")
	}
	declarations = append(declarations, RoleDeclaration{Kind: "client_role", Client: "portal", Name: "finance", Ref: "finance"})
	index = indexDeclaredRoles(declarations)
	path := keycloak.GroupRolePath{Client: "portal", Roles: []keycloak.RealmRole{{ID: "root", Name: "finance", ClientRole: true, ContainerID: "portal-uuid"}, {ID: "foreign", Name: "finance", ClientRole: true, ContainerID: "other-client-uuid"}, {ID: "observed-role-uuid", Name: "reader"}}}
	if _, ok := index.chain(path); ok {
		t.Fatal("cross-client role was labelled as the root client")
	}
}
