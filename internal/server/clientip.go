package server

import (
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/abinnovision/gh-token-broker/internal/config"
)

// clientIP resolves the client IP of r. Without proxy it is the TCP peer.
// With proxy and trustedProxies set, a peer outside them is a direct client:
// the header is ignored and the peer is used. Otherwise the result is the
// header entry proxy.Hops positions from the right; every trusted proxy
// appends its peer, so entries a client injects sit further left and are never
// selected. A missing or unusable entry yields the invalid zero Addr, never the
// proxy's own address.
func clientIP(r *http.Request, proxy *config.ProxyConfig) netip.Addr {
	if proxy == nil {
		return remoteAddr(r)
	}
	if len(proxy.TrustedPrefixes) > 0 {
		peer := remoteAddr(r)
		if !slices.ContainsFunc(proxy.TrustedPrefixes, func(p netip.Prefix) bool { return p.Contains(peer) }) {
			return peer
		}
	}
	var entries []string
	for _, v := range r.Header.Values(proxy.Header) {
		entries = append(entries, strings.Split(v, ",")...)
	}
	if proxy.Hops < 1 || len(entries) < proxy.Hops {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(entries[len(entries)-proxy.Hops]))
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap().WithZone("")
}

// remoteAddr parses the host of r.RemoteAddr.
func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap().WithZone("")
}

// sourceIPString renders ip for the audit log, empty when unknown.
func sourceIPString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}
