package main

import (
	"fmt"
	"go/ast"
	"strings"

	"golang.org/x/tools/go/packages"
)

// docIndex maps Go declarations to their GoDoc comments. This is the
// bridge that fuses the issue #43 pillars: the field's doc comment in
// the source IS the generated property description, so documenting
// the contract for `go doc` readers documents it for API consumers in
// the same edit.
//
// Keys are "pkgpath.TypeName" for type docs and
// "pkgpath.TypeName.FieldName" for field docs.
type docIndex struct {
	types  map[string]string
	fields map[string]string
}

// loadDocIndex parses the packages named by pkgPaths (resolved from
// dir, which must sit inside the module) and records every struct
// type's doc comment and every struct field's doc comment. Module
// dependencies (opencaravan-go) resolve from the module cache, so
// protocol types carry their upstream docs into the spec.
func loadDocIndex(dir string, pkgPaths []string) (*docIndex, error) {
	if len(pkgPaths) == 0 {
		return &docIndex{types: map[string]string{}, fields: map[string]string{}}, nil
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedCompiledGoFiles,
		Dir:  dir,
	}
	pkgs, err := packages.Load(cfg, pkgPaths...)
	if err != nil {
		return nil, fmt.Errorf("load packages %v: %w", pkgPaths, err)
	}
	idx := &docIndex{types: map[string]string{}, fields: map[string]string{}}
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			return nil, fmt.Errorf("load package %s: %v", pkg.PkgPath, pkg.Errors[0])
		}
		for _, file := range pkg.Syntax {
			idx.indexFile(pkg.PkgPath, file)
		}
	}
	return idx, nil
}

func (idx *docIndex) indexFile(pkgPath string, file *ast.File) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			doc := ts.Doc
			if doc == nil {
				doc = gen.Doc
			}
			typeKey := pkgPath + "." + ts.Name.Name
			if text := cleanDoc(doc.Text()); text != "" {
				idx.types[typeKey] = text
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range st.Fields.List {
				fdoc := field.Doc
				if fdoc == nil {
					fdoc = field.Comment
				}
				text := cleanDoc(fdoc.Text())
				if text == "" {
					continue
				}
				for _, name := range field.Names {
					idx.fields[typeKey+"."+name.Name] = text
				}
			}
		}
	}
}

// typeDoc returns the doc comment for pkgpath.TypeName, "" when
// undocumented.
func (idx *docIndex) typeDoc(pkgPath, typeName string) string {
	return idx.types[pkgPath+"."+typeName]
}

// fieldDoc returns the doc comment for a struct field, "" when
// undocumented.
func (idx *docIndex) fieldDoc(pkgPath, typeName, fieldName string) string {
	return idx.fields[pkgPath+"."+typeName+"."+fieldName]
}

// cleanDoc normalizes a GoDoc comment for use as an OpenAPI
// description: trims the trailing newline ast.CommentGroup.Text
// leaves and drops any trailing blank lines, but preserves interior
// paragraph breaks.
func cleanDoc(text string) string {
	return strings.TrimRight(text, "\n")
}
