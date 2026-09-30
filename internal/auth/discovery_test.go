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
	"sync"
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

// fakeIssuer is a TLS OIDC issuer whose JWKS and discovery issuer can be
// changed while it runs.
type fakeIssuer struct {
	*httptest.Server
	fetches atomic.Int32 // JWKS requests served

	mu         sync.Mutex
	keys       map[string]*rsa.PublicKey // kid -> key
	jwksStatus int                       // non-zero overrides the JWKS response
	jwksBody   string
	issuer     string
}

func (f *fakeIssuer) setKeys(keys map[string]*rsa.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = keys
}

// setJWKS makes the JWKS endpoint answer with status and the raw body.
func (f *fakeIssuer) setJWKS(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksStatus, f.jwksBody = status, body
}

func (f *fakeIssuer) setIssuer(issuer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issuer = issuer
}

// oidcServer serves a discovery document and a JWKS holding key under kid k1.
// The document omits jwks_uri when jwksURI returns an empty string.
func oidcServer(t *testing.T, key *rsa.PrivateKey, jwksURI func(base string) string) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{keys: map[string]*rsa.PublicKey{"k1": &key.PublicKey}}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		keys, status, raw, issuer := f.keys, f.jwksStatus, f.jwksBody, f.issuer
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var body any
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if issuer == "" {
				issuer = f.URL
			}
			doc := map[string]string{"issuer": issuer}
			if uri := jwksURI(f.URL); uri != "" {
				doc["jwks_uri"] = uri
			}
			body = doc
		case "/jwks":
			f.fetches.Add(1)
			if status != 0 {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(raw))
				return
			}
			set := jose.JSONWebKeySet{}
			for kid, k := range keys {
				set.Keys = append(set.Keys, jose.JSONWebKey{Key: k, KeyID: kid, Algorithm: "RS256", Use: "sig"})
			}
			body = set
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(f.Close)
	return f
}

// discoveryToken signs a token for the issuer at issuerURL. An empty kid
// omits the kid header.
func discoveryToken(t *testing.T, issuerURL string, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuerURL, "aud": "broker", "sub": "s", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// discoveredAuth builds an Authenticator for srv through OIDC discovery.
func discoveredAuth(t *testing.T, srv *fakeIssuer) *Authenticator {
	t.Helper()
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
	return a
}

func TestDiscoveryVerifiesAndThrottlesKeyFetches(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := oidcServer(t, key, func(base string) string { return base + "/jwks" })
	a := discoveredAuth(t, srv)
	token := func(kid string) string { return discoveryToken(t, srv.URL, key, kid) }

	if _, err := a.Authenticate(context.Background(), token("k1")); err != nil {
		t.Fatal(err)
	}
	// An unknown kid forces a refetch, which is throttled.
	if _, err := a.Authenticate(context.Background(), token("unknown")); err == nil {
		t.Fatal("token with unknown kid must be rejected")
	}
	if n := srv.fetches.Load(); n != 1 {
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
	srv := oidcServer(t, key, func(base string) string { return strings.Replace(base, "https://", "http://", 1) + "/jwks" })
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

func TestKeyRotation(t *testing.T) {
	old := jwksFetchInterval
	jwksFetchInterval = 100 * time.Millisecond
	t.Cleanup(func() { jwksFetchInterval = old })

	key1, key2 := mustRSAKey(t), mustRSAKey(t)
	srv := oidcServer(t, key1, func(base string) string { return base + "/jwks" })
	a := discoveredAuth(t, srv)

	if _, err := a.Authenticate(context.Background(), discoveryToken(t, srv.URL, key1, "k1")); err != nil {
		t.Fatal(err)
	}
	srv.setKeys(map[string]*rsa.PublicKey{"k2": &key2.PublicKey})

	time.Sleep(jwksFetchInterval)
	if _, err := a.Authenticate(context.Background(), discoveryToken(t, srv.URL, key2, "k2")); err != nil {
		t.Fatalf("token signed with the rotated-in key rejected: %v", err)
	}

	time.Sleep(jwksFetchInterval)
	_, err := a.Authenticate(context.Background(), discoveryToken(t, srv.URL, key1, "k1"))
	if err == nil {
		t.Fatal("token signed with the rotated-out key must be rejected")
	}
	t.Logf("rejected: %v", err)
	// The rejection follows a fresh fetch rather than the throttle.
	if n := srv.fetches.Load(); n != 3 {
		t.Fatalf("JWKS fetched %d times, want 3", n)
	}
}

func TestJWKSOutageFailsClosed(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"server error": {http.StatusInternalServerError, strings.Repeat("a", 4096)},
		"invalid JSON": {http.StatusOK, "{not json"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			key := mustRSAKey(t)
			srv := oidcServer(t, key, func(base string) string { return base + "/jwks" })
			srv.setJWKS(tc.status, tc.body)
			a := discoveredAuth(t, srv)

			_, err := a.Authenticate(context.Background(), discoveryToken(t, srv.URL, key, "k1"))
			if err == nil {
				t.Fatal("token must be rejected while the JWKS is unavailable")
			}
			t.Logf("rejected: %v", err)
			if len(err.Error()) > 300 {
				t.Fatalf("error includes unbounded response body (%d bytes)", len(err.Error()))
			}
		})
	}
}

func TestTokenWithoutKid(t *testing.T) {
	key, other := mustRSAKey(t), mustRSAKey(t)
	cases := map[string]struct {
		signer *rsa.PrivateKey
		ok     bool
	}{
		"published key": {key, true},
		"other key":     {other, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// A fresh issuer per case keeps the key fetch unthrottled.
			srv := oidcServer(t, key, func(base string) string { return base + "/jwks" })
			a := discoveredAuth(t, srv)
			_, err := a.Authenticate(context.Background(), discoveryToken(t, srv.URL, tc.signer, ""))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil {
				t.Logf("rejected: %v", err)
			}
		})
	}
}

func TestDiscoveryRejectsIssuerMismatch(t *testing.T) {
	srv := oidcServer(t, mustRSAKey(t), func(base string) string { return base + "/jwks" })
	srv.setIssuer("https://other.example.com")
	_, err := discover(context.Background(), srv.URL, srv.Client().Transport)
	if err == nil {
		t.Fatal("discovery document naming another issuer must be rejected")
	}
	t.Logf("rejected: %v", err)
}

func TestDiscoveryRejectsMissingJWKSURI(t *testing.T) {
	srv := oidcServer(t, mustRSAKey(t), func(string) string { return "" })
	_, err := discover(context.Background(), srv.URL, srv.Client().Transport)
	if err == nil {
		t.Fatal("discovery document without jwks_uri must be rejected")
	}
	t.Logf("rejected: %v", err)
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
