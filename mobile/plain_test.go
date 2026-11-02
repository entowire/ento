//go:build linux

package mobile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// An error type that cannot be a map key, as agent.httpError (it holds a slice).
type sliceError struct{ parts []string }

func (e sliceError) Error() string { return strings.Join(e.parts, ", ") }

// gomobile keeps the errors it hands to Java in a map: one that cannot be a key panics the app.
func TestPlainError(t *testing.T) {
	var err error = sliceError{parts: []string{"a", "b"}}
	plain(&err)
	m := map[any]bool{}
	m[err] = true // panics for sliceError itself
	if err.Error() != "a, b" {
		t.Fatal(err)
	}
	var none error
	plain(&none)
	if none != nil {
		t.Fatal(none)
	}
}

// Every exported function that returns an error to the app passes it through plain.
func TestExportedErrorsArePlain(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			res := fn.Type.Results.List
			last := res[len(res)-1]
			if id, ok := last.Type.(*ast.Ident); !ok || id.Name != "error" {
				continue
			}
			deferred := false
			for _, st := range fn.Body.List {
				if ds, ok := st.(*ast.DeferStmt); ok {
					if id, ok := ds.Call.Fun.(*ast.Ident); ok && id.Name == "plain" {
						deferred = true
					}
				}
			}
			if !deferred || len(last.Names) == 0 {
				t.Errorf("%s: %s returns an error without `defer plain(&err)` on a named result", f, fn.Name.Name)
			}
		}
	}
}
