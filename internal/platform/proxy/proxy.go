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
	// TrustClientCertHeaders enables X-Forwarded-Tls-Client-Cert* handling
	// for trusted peers. Kept distinct from TrustForwardedHeaders so an
	// operator can accept proxied IP/scheme/host without also accepting
	// proxied client identity (or vice versa). Direct mTLS extraction
	// from [http.Request.TLS] always runs regardless of this flag,
	// because that path is authenticated by the TLS layer rather than
	// by trusting a peer's HTTP header.
	TrustClientCertHeaders bool
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
	// ClientCert is the leaf client certificate metadata, populated when
	// either the TLS layer presented a peer certificate directly or a
	// trusted proxy forwarded one via X-Forwarded-Tls-Client-Cert*
	// headers. Nil when no client cert is present or the source could
	// not be trusted.
	ClientCert *ClientCert
}

// RequestInfoFrom returns client-facing request metadata. Forwarded
// headers and proxied client-cert headers are used only when their
// respective Config flags are set AND the immediate peer is in a
// trusted network.
//
// Client-cert extraction has a separate precedence from the
// IP/scheme/host fields: a cert presented over direct mTLS
// (r.TLS.PeerCertificates) is always honored because the TLS layer
// authenticated the peer. Proxied cert headers are only honored when
// the peer is in TrustedNetworks AND Config.TrustClientCertHeaders is
// set.
func RequestInfoFrom(r *http.Request, cfg Config) RequestInfo {
	remoteIP := remoteAddrIP(r.RemoteAddr)
	info := RequestInfo{
		ClientIP: remoteIP,
		Scheme:   requestScheme(r),
		Host:     r.Host,
	}

	// Direct mTLS path always runs: this is authenticated by TLS, not
	// by trusting an HTTP header from a peer.
	if cert := clientCertFromTLS(r); cert != nil {
		info.ClientCert = cert
	}

	trustedPeer := isTrusted(remoteIP, cfg.TrustedNetworks)
	if !cfg.TrustForwardedHeaders && !cfg.TrustClientCertHeaders {
		return info
	}
	if !trustedPeer {
		return info
	}

	if cfg.TrustForwardedHeaders {
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
	}

	if cfg.TrustClientCertHeaders && info.ClientCert == nil {
		if pemHeader := r.Header.Get(headerForwardedClientCert); pemHeader != "" {
			info.ClientCert = parseForwardedClientCertPEM(pemHeader)
		}
		if info.ClientCert == nil {
			if infoHeader := r.Header.Get(headerForwardedClientCertInfo); infoHeader != "" {
				info.ClientCert = parseForwardedClientCertInfo(infoHeader)
			}
		}
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
