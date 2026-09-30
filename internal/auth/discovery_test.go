package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"

	"github.com/abinnovision/gh-token-broker/internal/config"
)

func get(t *testing.T, client *http.Client, url string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	return err
}

func TestTransportRejectsPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	client, _ := newClient(srv.Client().Transport)
	if err := get(t, client, srv.URL); err == nil {
		t.Fatal("plain http request must fail")
	}
}

func TestTransportCapsResponseBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxResponseBytes+1))
	}))
	defer srv.Close()
	client, _ := newClient(srv.Client().Transport)
	if err := get(t, client, srv.URL); err == nil {
		t.Fatal("oversized response body must fail")
	}
}

func TestTransportThrottlesJWKS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	client, tr := newClient(srv.Client().Transport)
	tr.jwksURL = srv.URL + "/jwks"

	if err := get(t, client, tr.jwksURL); err != nil {
		t.Fatal(err)
	}
	if err := get(t, client, tr.jwksURL); err == nil {
		t.Fatal("second JWKS fetch within the interval must fail")
	}
	if err := get(t, client, srv.URL+"/other"); err != nil {
		t.Fatalf("non-JWKS request throttled: %v", err)
	}
	tr.lastJWKSFetch = time.Now().Add(-jwksFetchInterval)
	if err := get(t, client, tr.jwksURL); err != nil {
		t.Fatalf("JWKS fetch after the interval failed: %v", err)
	}
}

func TestRedirectLimits(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/plain":
			http.Redirect(w, r, plain.URL, http.StatusFound)
		case "/hops":
			http.Redirect(w, r, "/hop2", http.StatusFound)
		case "/hop2":
			http.Redirect(w, r, "/hop3", http.StatusFound)
		case "/hop3":
			http.Redirect(w, r, "/done", http.StatusFound)
		}
	}))
	defer srv.Close()
	client, _ := newClient(srv.Client().Transport)

	if err := get(t, client, srv.URL+"/hops"); err != nil {
		t.Fatalf("three redirects must be followed: %v", err)
	}
	if err := get(t, client, srv.URL+"/loop"); err == nil {
		t.Fatal("redirect loop must fail")
	}
	if err := get(t, client, srv.URL+"/plain"); err == nil {
		t.Fatal("redirect to plain http must fail")
	}
}

// oidcServer serves a discovery document and a JWKS holding key under kid k1.
func oidcServer(t *testing.T, key *rsa.PrivateKey, jwksURI func(base string) string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var fetches atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body any
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			body = map[string]string{"issuer": srv.URL, "jwks_uri": jwksURI(srv.URL)}
		case "/jwks":
			fetches.Add(1)
			body = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &fetches
}

func TestDiscoveryVerifiesAndThrottlesKeyFetches(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv, fetches := oidcServer(t, key, func(base string) string { return base + "/jwks" })
	iss := config.OIDCIssuer{
		Name: "test", Issuer: srv.URL, Audience: "broker", Algorithms: []string{"RS256"},
		MaxTokenLifetimeSeconds: 3600, Claims: []string{"sub"},
	}
	a, err := newAuthenticator([]config.OIDCIssuer{iss}, time.Minute, func(iss config.OIDCIssuer) (oidc.KeySet, error) {
		return discover(context.Background(), iss.Issuer, srv.Client().Transport)
	})
	if err != nil {
		t.Fatal(err)
	}
	token := func(kid string) string {
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": srv.URL, "aud": "broker", "sub": "s", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		})
		tok.Header["kid"] = kid
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	if _, err := a.Authenticate(context.Background(), token("k1")); err != nil {
		t.Fatal(err)
	}
	// An unknown kid forces a refetch, which is throttled.
	if _, err := a.Authenticate(context.Background(), token("unknown")); err == nil {
		t.Fatal("token with unknown kid must be rejected")
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("JWKS fetched %d times, want 1", n)
	}
	if _, err := a.Authenticate(context.Background(), token("k1")); err != nil {
		t.Fatalf("cached key no longer accepted: %v", err)
	}
}

func TestDiscoveryRejectsPlainHTTPJWKSURI(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := oidcServer(t, key, func(base string) string { return strings.Replace(base, "https://", "http://", 1) + "/jwks" })
	if _, err := discover(context.Background(), srv.URL, srv.Client().Transport); err == nil {
		t.Fatal("http jwks_uri must be rejected")
	}
}

func TestDiscoveryBoundsErrorFromResponseBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("a", maxResponseBytes/2)))
	}))
	defer srv.Close()
	_, err := discover(context.Background(), srv.URL, srv.Client().Transport)
	if err == nil {
		t.Fatal("discovery must fail on a non-200 response")
	}
	if len(err.Error()) > 300 {
		t.Fatalf("error includes unbounded response body (%d bytes)", len(err.Error()))
	}
}
