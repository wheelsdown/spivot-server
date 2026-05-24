// Package proxy contains helpers for interpreting reverse-proxy request
// metadata without making the HTTP server depend on a specific edge proxy.
package proxy

import (
	"net"
	"net/http"
	"strings"
)

// DefaultTrustedProxyCIDRs returns the private and loopback ranges commonly
// used between a reverse proxy and an application container.
func DefaultTrustedProxyCIDRs() []string {
	return []string{
		"127.0.0.1/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}
}

// Config controls whether forwarded request metadata is trusted.
type Config struct {
	// TrustForwardedHeaders enables X-Forwarded-* handling for trusted peers.
	TrustForwardedHeaders bool
	// TrustedNetworks contains immediate proxy networks allowed to set headers.
	TrustedNetworks []*net.IPNet
}

// ParseCIDRs parses trusted proxy CIDR strings.
func ParseCIDRs(values []string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}
	return networks, nil
}

// RequestInfo is the client-facing request metadata after applying trusted
// reverse-proxy headers.
type RequestInfo struct {
	// ClientIP is the original client IP when trusted headers are present.
	ClientIP string
	// Scheme is the externally visible request scheme.
	Scheme string
	// Host is the externally visible request host.
	Host string
	// TrustedProxy reports whether forwarded headers were accepted.
	TrustedProxy bool
}

// RequestInfoFrom returns client-facing request metadata. Forwarded headers
// are used only when enabled and the immediate peer is in a trusted network.
func RequestInfoFrom(r *http.Request, cfg Config) RequestInfo {
	remoteIP := remoteAddrIP(r.RemoteAddr)
	info := RequestInfo{
		ClientIP: remoteIP,
		Scheme:   requestScheme(r),
		Host:     r.Host,
	}

	if !cfg.TrustForwardedHeaders || !isTrusted(remoteIP, cfg.TrustedNetworks) {
		return info
	}
	info.TrustedProxy = true

	if forwardedFor := firstForwardedValue(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
		if ip := net.ParseIP(forwardedFor); ip != nil {
			info.ClientIP = ip.String()
		}
	}
	if proto := firstForwardedValue(r.Header.Get("X-Forwarded-Proto")); proto == "http" || proto == "https" {
		info.Scheme = proto
	}
	if host := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); host != "" {
		info.Host = host
	}

	return info
}

func remoteAddrIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	return ip.String()
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func isTrusted(remoteIP string, networks []*net.IPNet) bool {
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func firstForwardedValue(value string) string {
	first, _, _ := strings.Cut(value, ",")
	return strings.TrimSpace(first)
}
