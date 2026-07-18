// Package docs serves the embedded API reference explorer.
//
// The explorer is Scalar (https://github.com/scalar/scalar), vendored
// as the self-contained browser bundle so /docs/ works with no CDN or
// network dependency. The page loads the OpenAPI document from the
// URL the server passes to [PageHandler] — the same generated spec
// served at /openapi.json — so the explorer can never disagree with
// the contract the server actually implements.
//
// Vendored asset provenance:
//
//	assets/scalar.standalone.js.gz
//	  @scalar/api-reference 1.62.9 (MIT license)
//	  https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.62.9/dist/browser/standalone.js
//	  sha256 (uncompressed): 9f4c76a736c3f39c513ecc874f59183d90295eb2a9f1e1b0228c9a8f66ab0982
//	  sha256 (gzipped):      1006624205fc957c1a4b826bac9fd93e58a9da80e5542257494f2fe783478841
//
// To upgrade: download the pinned standalone.js for the new version,
// verify it still contains no dynamic imports (`grep -c "import("`
// must be 0 — the bundle must stay offline-capable), gzip -9 it into
// assets/, and update the provenance block above.
package docs

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	_ "embed"
)

// ScalarAssetName is the URL basename the explorer page loads the
// Scalar bundle from. Exposed so the server can register the asset
// route under the same prefix as the page without hardcoding the
// name twice.
const ScalarAssetName = "scalar.standalone.js"

//go:embed assets/scalar.standalone.js.gz
var scalarJSGzip []byte

// pageTemplate is the explorer shell. withDefaultFonts is disabled so
// Scalar does not try to fetch webfonts from its CDN — the page must
// render fully offline.
var pageTemplate = template.Must(template.New("docs").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Spivot Server API</title>
</head>
<body>
  <div id="app"></div>
  <script src="{{.AssetName}}"></script>
  <script>
    Scalar.createApiReference('#app', {
      url: '{{.SpecURL}}',
      withDefaultFonts: false,
    })
  </script>
</body>
</html>
`))

// PageHandler returns the handler for the explorer page itself.
// specURL is the URL the browser should fetch the OpenAPI document
// from, resolved relative to the page. The page references the
// Scalar bundle by [ScalarAssetName] relative to its own URL, so the
// caller must register [ScalarAssetHandler] as a sibling route.
func PageHandler(specURL string) http.Handler {
	var page strings.Builder
	err := pageTemplate.Execute(&page, struct {
		AssetName string
		SpecURL   string
	}{AssetName: ScalarAssetName, SpecURL: specURL})
	if err != nil {
		// The template and its inputs are compile-time constants;
		// failure here is a programmer error caught by any test
		// that touches the docs route.
		panic(fmt.Sprintf("docs: rendering explorer page: %v", err))
	}
	body := []byte(page.String())
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(body)
	})
}

// ScalarAssetHandler returns the handler serving the vendored Scalar
// JavaScript bundle. The asset is stored gzipped; clients that accept
// gzip (every browser) get the compressed bytes as-is, anyone else
// gets a streaming decompression.
func ScalarAssetHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		// The bundle is version-pinned and only changes with a new
		// server build; a day of caching keeps repeat visits fast
		// without wedging upgrades for long.
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(scalarJSGzip)
			return
		}
		gz, err := gzip.NewReader(bytes.NewReader(scalarJSGzip))
		if err != nil {
			http.Error(w, "embedded asset corrupt", http.StatusInternalServerError)
			return
		}
		defer func() { _ = gz.Close() }()
		_, _ = io.Copy(w, gz)
	})
}
