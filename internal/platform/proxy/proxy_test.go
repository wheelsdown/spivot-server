package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestInfoFromIgnoresForwardedHeadersByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://internal.example/health", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "spivot.example.com")

	info := RequestInfoFrom(req, Config{})

	if info.ClientIP != "127.0.0.1" {
		t.Fatalf("ClientIP = %q, want 127.0.0.1", info.ClientIP)
	}
	if info.Scheme != "http" {
		t.Fatalf("Scheme = %q, want http", info.Scheme)
	}
	if info.Host != "internal.example" {
		t.Fatalf("Host = %q, want internal.example", info.Host)
	}
	if info.TrustedProxy {
		t.Fatal("TrustedProxy = true, want false")
	}
}

func TestRequestInfoFromTrustsForwardedHeadersFromTrustedNetwork(t *testing.T) {
	networks, err := ParseCIDRs([]string{"127.0.0.1/8"})
	if err != nil {
		t.Fatalf("parse CIDRs: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://internal.example/health", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 127.0.0.1")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "spivot.example.com")

	info := RequestInfoFrom(req, Config{
		TrustForwardedHeaders: true,
		TrustedNetworks:       networks,
	})

	if info.ClientIP != "203.0.113.10" {
		t.Fatalf("ClientIP = %q, want 203.0.113.10", info.ClientIP)
	}
	if info.Scheme != "https" {
		t.Fatalf("Scheme = %q, want https", info.Scheme)
	}
	if info.Host != "spivot.example.com" {
		t.Fatalf("Host = %q, want spivot.example.com", info.Host)
	}
	if !info.TrustedProxy {
		t.Fatal("TrustedProxy = false, want true")
	}
}

func TestRequestInfoFromRejectsForwardedHeadersFromUntrustedPeer(t *testing.T) {
	networks, err := ParseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse CIDRs: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://internal.example/health", nil)
	req.RemoteAddr = "198.51.100.20:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "spivot.example.com")

	info := RequestInfoFrom(req, Config{
		TrustForwardedHeaders: true,
		TrustedNetworks:       networks,
	})

	if info.ClientIP != "198.51.100.20" {
		t.Fatalf("ClientIP = %q, want 198.51.100.20", info.ClientIP)
	}
	if info.Scheme != "http" {
		t.Fatalf("Scheme = %q, want http", info.Scheme)
	}
	if info.Host != "internal.example" {
		t.Fatalf("Host = %q, want internal.example", info.Host)
	}
	if info.TrustedProxy {
		t.Fatal("TrustedProxy = true, want false")
	}
}
