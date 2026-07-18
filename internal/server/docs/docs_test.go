package docs

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPageHandlerRendersExplorerShell(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/docs/", nil)
	rec := httptest.NewRecorder()
	PageHandler("/openapi.json").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{ScalarAssetName, "/openapi.json", "Scalar.createApiReference", "withDefaultFonts: false"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestScalarAssetHandler(t *testing.T) {
	t.Run("gzip-capable client gets compressed bytes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/docs/"+ScalarAssetName, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		ScalarAssetHandler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatalf("response is not valid gzip: %v", err)
		}
		defer func() { _ = gz.Close() }()
		if _, err := io.Copy(io.Discard, gz); err != nil {
			t.Fatalf("decompress response: %v", err)
		}
	})

	t.Run("plain client gets decompressed bundle", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/docs/"+ScalarAssetName, nil)
		rec := httptest.NewRecorder()
		ScalarAssetHandler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("Content-Encoding = %q, want none", got)
		}
		// The vendored bundle opens with Scalar's banner comment; a
		// couple MB of JS proves decompression actually ran.
		if rec.Body.Len() < 1<<20 {
			t.Fatalf("decompressed bundle suspiciously small: %d bytes", rec.Body.Len())
		}
		if !strings.HasPrefix(rec.Body.String(), "/**") {
			t.Errorf("bundle does not start with the expected banner comment")
		}
	})
}
