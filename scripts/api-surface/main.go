// Command api-surface records compiler-resolved Go contracts used by fixtures.
// It reads export data from the selected toolchain, without importing runtime
// code into the operator or executing package initializers.
package main

import (
	"encoding/json"
	"fmt"
	"go/importer"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"strings"
)

type listedPackage struct {
	ImportPath string
	Export     string
	DepOnly    bool
	Error      *struct{ Err string }
}

func qualifier(pkg *types.Package) string { return pkg.Path() }

func describe(pkg *types.Package) map[string]string {
	result := make(map[string]string)
	format := func(t types.Type) string { return types.TypeString(t, qualifier) }
	for _, name := range pkg.Scope().Names() {
		object := pkg.Scope().Lookup(name)
		if !object.Exported() {
			continue
		}
		switch value := object.(type) {
		case *types.Const:
			result[name] = "const " + format(value.Type()) + " = " + value.Val().ExactString()
		case *types.Var:
			result[name] = "var " + format(value.Type())
		case *types.Func:
			result[name] = format(value.Type())
		case *types.TypeName:
			if value.IsAlias() {
				result[name] = "alias " + format(types.Unalias(value.Type()))
			} else {
				result[name] = "type " + format(value.Type().Underlying())
			}
			if generic, ok := value.Type().(interface{ TypeParams() *types.TypeParamList }); ok {
				for index := 0; index < generic.TypeParams().Len(); index++ {
					parameter := generic.TypeParams().At(index)
					result[name] += " [" + parameter.Obj().Name() + " " + format(parameter.Constraint()) + "]"
				}
			}
			for _, receiver := range []struct {
				prefix string
				typeOf types.Type
			}{{name, value.Type()}, {"*" + name, types.NewPointer(value.Type())}} {
				methods := types.NewMethodSet(receiver.typeOf)
				for index := 0; index < methods.Len(); index++ {
					method := methods.At(index)
					if method.Obj().Exported() {
						result[receiver.prefix+"."+method.Obj().Name()] = format(method.Type())
					}
				}
			}
		}
	}
	return result
}

func snapshot(patterns []string) (map[string]map[string]string, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("at least one reviewed package is required")
	}
	for _, pattern := range patterns {
		if !strings.HasPrefix(pattern, "./") || strings.Contains(pattern, "..") || strings.ContainsAny(pattern, "\n\r") {
			return nil, fmt.Errorf("only exact local package paths are accepted")
		}
	}
	command := exec.Command("go", append([]string{"list", "-deps", "-export", "-json"}, patterns...)...)
	data, err := command.Output()
	if err != nil || len(data) > 32<<20 {
		return nil, fmt.Errorf("Go export inventory failed or exceeded its budget")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	exports := make(map[string]string)
	var roots []string
	for {
		var pkg listedPackage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("invalid Go export inventory")
		}
		if pkg.Error != nil {
			return nil, fmt.Errorf("Go export inventory contains a package error")
		}
		exports[pkg.ImportPath] = pkg.Export
		if !pkg.DepOnly {
			roots = append(roots, pkg.ImportPath)
		}
	}
	if len(roots) != len(patterns) {
		return nil, fmt.Errorf("Go API package selection was expanded or incomplete")
	}
	reader := importer.ForCompiler(token.NewFileSet(), "gc", func(path string) (io.ReadCloser, error) {
		filename := exports[path]
		if filename == "" {
			return nil, fmt.Errorf("missing dependency export")
		}
		return os.Open(filename)
	})
	result := make(map[string]map[string]string)
	for _, path := range roots {
		pkg, err := reader.Import(path)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve selected API from toolchain export data")
		}
		result[path] = describe(pkg)
	}
	return result, nil
}

func main() {
	result, err := snapshot(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		os.Exit(1)
	}
}
