package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func fixtureSurface(t *testing.T, body string) map[string]string {
	t.Helper()
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, "fixture.go", "package fixture\n"+body, 0)
	if err != nil {
		t.Fatal(err)
	}
	config := &types.Config{}
	pkg, err := config.Check("example.test/fixture", files, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return describe(pkg)
}

func TestExportedSurfaceDetectsSemanticBreaks(t *testing.T) {
	const original = "type Value struct { Name string `json:\"name\"` }; type Reader interface { Read(string) error }; const Format = 1; func (v *Value) Check(s string) error { return nil }; func Build(v Value) *Value { return nil }"
	baseline := fixtureSurface(t, original)
	for name, changed := range map[string]string{
		"field":          strings.Replace(original, "Name string", "Title string", 1),
		"field type":     strings.Replace(original, "Name string", "Name []string", 1),
		"tag":            strings.Replace(original, "json:\"name\"", "json:\"title\"", 1),
		"constant":       strings.Replace(original, "Format = 1", "Format = 2", 1),
		"signature":      strings.Replace(original, "Build(v Value)", "Build(v *Value)", 1),
		"interface":      strings.Replace(original, "Read(string) error", "Read(string) error; Close() error", 1),
		"pointer method": strings.Replace(original, "Check(s string)", "Check(s []string)", 1),
		"alias":          strings.Replace(original, "type Value struct", "type Value = struct", 1),
	} {
		t.Run(name, func(t *testing.T) {
			// Methods cannot be declared on an unnamed alias; test that case separately.
			if name == "alias" {
				before := fixtureSurface(t, "type Other string; type Value Other")
				after := fixtureSurface(t, "type Other string; type Value = Other")
				if reflect.DeepEqual(before, after) {
					t.Fatal("alias transition was hidden")
				}
				return
			}
			if reflect.DeepEqual(baseline, fixtureSurface(t, changed)) {
				t.Fatal("exported API break was hidden")
			}
		})
	}
	if _, ok := baseline["*Value.Check"]; !ok {
		t.Fatal("pointer methods omitted")
	}
}

func TestExportedSurfaceIncludesPromotedMethodsAndGenericConstraints(t *testing.T) {
	before := fixtureSurface(t, "type Embedded struct{}; func (Embedded) Read(s string) {}; type Value struct { Embedded }; type Set[T ~string] []T")
	after := fixtureSurface(t, "type Embedded struct{}; func (Embedded) Read(s []string) {}; type Value struct { Embedded }; type Set[T ~int] []T")
	for _, name := range []string{"Value.Read", "*Value.Read", "Set"} {
		if before[name] == "" || before[name] == after[name] {
			t.Fatal("promoted method or generic constraint drift omitted", name)
		}
	}
}

func TestSnapshotRefusesUnreviewedPackageExpansion(t *testing.T) {
	for _, patterns := range [][]string{nil, {"../elsewhere"}, {"./../elsewhere"}, {"./..."}, {"./api\n"}} {
		if _, err := snapshot(patterns, strings.NewReader("")); err == nil {
			t.Fatal("unreviewed package path accepted")
		}
	}
}

func TestSnapshotResolvesLocalPackageAndExternalTypesWithoutExecutingIt(t *testing.T) {
	inventory, err := exec.Command("go", "list", "-deps", "-export", "-json", "./testdata/contract").Output()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := snapshot([]string{"./testdata/contract"}, bytes.NewReader(inventory))
	if err != nil {
		t.Fatal(err)
	}
	values := actual["github.com/Alien6-Studio/hankoshell-operator/tools/qualification/fixtures/api-surface/testdata/contract"]
	if !strings.Contains(values["Value"], "time.Time") || values["*Value.Ready"] != "func() bool" {
		t.Fatal("compiler export resolution lost an external type or method")
	}
}
