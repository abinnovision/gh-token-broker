package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/abinnovision/gh-token-broker/internal/config"
)

func TestClientIP(t *testing.T) {
	xff := &config.ProxyConfig{Header: "X-Forwarded-For", Hops: 1}
	trusted := &config.ProxyConfig{
		Header: "X-Forwarded-For", Hops: 1,
		TrustedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	tests := []struct {
		name       string
		remoteAddr string
		headers    [][2]string
		proxy      *config.ProxyConfig
		want       string
	}{
		{name: "no proxy ipv4", remoteAddr: "192.0.2.7:4000", want: "192.0.2.7"},
		{name: "no proxy ipv6", remoteAddr: "[2001:db8::1]:4000", want: "2001:db8::1"},
		{name: "no proxy ignores header", remoteAddr: "192.0.2.7:4000",
			headers: [][2]string{{"X-Forwarded-For", "203.0.113.9"}}, want: "192.0.2.7"},
		{name: "no proxy mapped ipv6", remoteAddr: "[::ffff:192.0.2.7]:4000", want: "192.0.2.7"},
		{name: "no proxy unparsable", remoteAddr: "garbage", want: ""},
		{name: "hops 1 ignores spoofed left entries", remoteAddr: "10.0.0.1:1", proxy: xff,
			headers: [][2]string{{"X-Forwarded-For", "10.9.9.9, 198.51.100.1, 203.0.113.5"}}, want: "203.0.113.5"},
		{name: "hops 2", remoteAddr: "10.0.0.1:1", proxy: &config.ProxyConfig{Header: "X-Forwarded-For", Hops: 2},
			headers: [][2]string{{"X-Forwarded-For", "10.9.9.9, 198.51.100.1, 10.0.0.2"}}, want: "198.51.100.1"},
		{name: "multiple header lines", remoteAddr: "10.0.0.1:1", proxy: xff,
			headers: [][2]string{{"X-Forwarded-For", "10.9.9.9"}, {"X-Forwarded-For", "198.51.100.1, 203.0.113.5"}},
			want:    "203.0.113.5"},
		{name: "single value header", remoteAddr: "10.0.0.1:1", proxy: &config.ProxyConfig{Header: "X-Real-Ip", Hops: 1},
			headers: [][2]string{{"X-Real-Ip", "203.0.113.5"}}, want: "203.0.113.5"},
		{name: "ipv6 entry", remoteAddr: "10.0.0.1:1", proxy: xff,
			headers: [][2]string{{"X-Forwarded-For", "2001:db8::5"}}, want: "2001:db8::5"},
		{name: "mapped ipv6 entry", remoteAddr: "10.0.0.1:1", proxy: xff,
			headers: [][2]string{{"X-Forwarded-For", "::ffff:203.0.113.5"}}, want: "203.0.113.5"},
		{name: "missing header fails closed", remoteAddr: "10.0.0.1:1", proxy: xff, want: ""},
		{name: "too few entries fails closed", remoteAddr: "10.0.0.1:1",
			proxy:   &config.ProxyConfig{Header: "X-Forwarded-For", Hops: 2},
			headers: [][2]string{{"X-Forwarded-For", "203.0.113.5"}}, want: ""},
		{name: "garbage entry fails closed", remoteAddr: "10.0.0.1:1", proxy: xff,
			headers: [][2]string{{"X-Forwarded-For", "203.0.113.5, unknown"}}, want: ""},
		{name: "entry with port fails closed", remoteAddr: "10.0.0.1:1", proxy: xff,
			headers: [][2]string{{"X-Forwarded-For", "203.0.113.5:8080"}}, want: ""},
		{name: "bracketed entry fails closed", remoteAddr: "10.0.0.1:1", proxy: xff,
			headers: [][2]string{{"X-Forwarded-For", "[2001:db8::5]"}}, want: ""},
		{name: "header entry zone stripped", remoteAddr: "10.0.0.1:1", proxy: xff,
			headers: [][2]string{{"X-Forwarded-For", "fe80::1%eth0"}}, want: "fe80::1"},
		{name: "remote addr zone stripped", remoteAddr: "[fe80::1%eth0]:4000", want: "fe80::1"},
		{name: "trusted peer uses header", remoteAddr: "10.0.0.1:1", proxy: trusted,
			headers: [][2]string{{"X-Forwarded-For", "10.9.9.9, 203.0.113.5"}}, want: "203.0.113.5"},
		{name: "direct peer with spoofed header gets its remote addr", remoteAddr: "198.51.100.8:1", proxy: trusted,
			headers: [][2]string{{"X-Forwarded-For", "203.0.113.5"}}, want: "198.51.100.8"},
		{name: "trusted peer without header is unknown", remoteAddr: "10.0.0.1:1", proxy: trusted, want: ""},
		{name: "trusted peer with garbage entry is unknown", remoteAddr: "10.0.0.1:1", proxy: trusted,
			headers: [][2]string{{"X-Forwarded-For", "unknown"}}, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/token", nil)
			r.RemoteAddr = tc.remoteAddr
			for _, h := range tc.headers {
				r.Header.Add(h[0], h[1])
			}
			got := clientIP(r, tc.proxy)
			want := netip.Addr{}
			if tc.want != "" {
				want = netip.MustParseAddr(tc.want)
			}
			if got != want {
				t.Fatalf("clientIP = %v, want %v", got, want)
			}
		})
	}
}
