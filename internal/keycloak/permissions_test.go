package keycloak

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminOperationDocumentationContract(t *testing.T) {
	var table strings.Builder
	table.WriteString("| Capability | Methods | Admin API path | Permission |\n| --- | --- | --- | --- |\n")
	seen := map[string]bool{}
	for _, operation := range AdminOperations() {
		if operation.Capability == "" || operation.Permission == "" {
			t.Fatal("unclassified operation")
		}
		for _, method := range strings.Split(operation.Methods, ",") {
			key := method + " " + operation.Path
			if seen[key] {
				t.Fatalf("duplicate operation: %s", key)
			}
			seen[key] = true
		}
		fmt.Fprintf(&table, "| %s | %s | `%s` | %s |\n", operation.Capability, operation.Methods, operation.Path, operation.Permission)
	}
	data, err := os.ReadFile("../../docs/keycloak-permissions.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "<!-- admin-operation-contract:start -->\n"+table.String()+"<!-- admin-operation-contract:end -->") {
		t.Fatal("Admin API permission contract changed: review real-Keycloak permissions and update docs/keycloak-permissions.md inventory")
	}
}

// Scan syntax, not source line numbers. Any direct network execution outside
// the reviewed gateway is a regression, including a helper in a new Go file.
func TestKeycloakNetworkCallsUsePermissionGateway(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				// Header.Get is a metadata read, not HTTP client execution.
				if field, ok := selector.X.(*ast.SelectorExpr); ok && field.Sel.Name == "Header" && selector.Sel.Name == "Get" {
					return true
				}
				switch selector.Sel.Name {
				case "Do", "RoundTrip", "Get", "Post", "PostForm", "Dial", "DialContext", "DialTLSContext":
					if path != "permissions.go" || function.Name.Name != "do" || selector.Sel.Name != "Do" {
						t.Errorf("%s: %s bypasses the permission gateway in %s", path, selector.Sel.Name, function.Name.Name)
					}
				}
				return true
			})
		}
	}
}

func TestPermissionGatewayRejectsUnclassifiedCalls(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests++; w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	client := New(server.URL+"/auth", "operator", "secret")
	for _, test := range []struct {
		method, path string
		allowed      bool
	}{
		{http.MethodGet, "/auth/admin/realms/managed/roles/a%2Fb", true},
		{http.MethodGet, "/auth/admin/realms/managed/group-by-path/team/nested", true},
		{http.MethodPost, "/auth/admin/realms/managed/users/user/impersonation", false},
		{http.MethodPost, "/auth/admin/realms/managed/new-api", false},
		{http.MethodPatch, "/auth/admin/realms/managed/clients/client", false},
		{http.MethodGet, "/authentication/admin/realms", false},
		{http.MethodGet, "/auth/admin/realms/managed/clients/client/unreviewed", false},
	} {
		req, err := http.NewRequest(test.method, server.URL+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.do(req)
		if response != nil {
			response.Body.Close()
		}
		if (err == nil) != test.allowed {
			t.Errorf("%s %s: allowed=%t error=%v", test.method, test.path, test.allowed, err)
		}
	}
	req, err := http.NewRequest(http.MethodGet, "https://outside.invalid/auth/admin/serverinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.do(req); err == nil {
		t.Fatal("out-of-origin request accepted")
	}
	if requests != 2 {
		t.Fatalf("unclassified calls reached the server: %d requests", requests)
	}
}

func TestPermissionGatewayDoesNotFollowRedirects(t *testing.T) {
	unreviewedCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/serverinfo" {
			http.Redirect(w, r, "/admin/realms/managed/users", http.StatusTemporaryRedirect)
			return
		}
		unreviewedCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := New(server.URL, "operator", "secret")
	req, err := http.NewRequest(http.MethodGet, server.URL+"/admin/serverinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect || unreviewedCalls != 0 {
		t.Fatal("redirect executed an unreviewed operation")
	}
}
