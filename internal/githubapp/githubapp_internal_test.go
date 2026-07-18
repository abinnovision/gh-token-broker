package githubapp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-github/v66/github"
)

func testClient(baseURL string, hc *http.Client) *Client {
	return &Client{baseURL: baseURL, httpClient: hc, logger: slog.New(slog.DiscardHandler)}
}

// TestMintScopedTokenFailsClosedOnEmptyScope proves INV-1: an empty computed
// repository set or permission map is refused and NO GitHub call is made.
func TestMintScopedTokenFailsClosedOnEmptyScope(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := testClient(srv.URL, srv.Client())

	cases := []struct {
		name  string
		repos []string
		perms map[string]string
	}{
		{"nil repos", nil, map[string]string{"contents": "read"}},
		{"empty repos", []string{}, map[string]string{"contents": "read"}},
		{"nil perms", []string{"app"}, nil},
		{"empty perms", []string{"app"}, map[string]string{}},
		{"both empty", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.MintScopedToken(context.Background(), 42, tc.repos, tc.perms)
			if !errors.Is(err, ErrEmptyScope) {
				t.Fatalf("want ErrEmptyScope, got %v", err)
			}
		})
	}
	if called {
		t.Fatal("GitHub must never be called for an empty computed scope")
	}
}

// TestMintScopedTokenSuccess exercises the happy path against a fake token
// endpoint, asserting the request body and the parsed response.
func TestMintScopedTokenSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/42/access_tokens" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"token": "ghs_abc123",
			"expires_at": "2026-07-09T12:00:00Z",
			"permissions": {"contents": "read"},
			"repositories": [{"name": "app"}]
		}`))
	}))
	defer srv.Close()
	c := testClient(srv.URL, srv.Client())

	tok, err := c.MintScopedToken(context.Background(), 42, []string{"app"}, map[string]string{"contents": "read"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Token != "ghs_abc123" {
		t.Errorf("token = %q", tok.Token)
	}
	if tok.Permissions["contents"] != "read" {
		t.Errorf("permissions = %v", tok.Permissions)
	}
	if len(tok.Repositories) != 1 || tok.Repositories[0] != "app" {
		t.Errorf("repositories = %v", tok.Repositories)
	}
	if tok.ExpiresAt.IsZero() {
		t.Error("expires_at not parsed")
	}
}

func TestMintScopedTokenSurfacesErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"not permitted"}`))
	}))
	defer srv.Close()
	c := testClient(srv.URL, srv.Client())

	_, err := c.MintScopedToken(context.Background(), 42, []string{"app"}, map[string]string{"contents": "read"})
	if err == nil {
		t.Fatal("expected error on non-201 response")
	}
}

// TestIntersectPermissionsMatrix covers INV-2 (per-key min level), the
// absent-key case, and the unknown-permission-key case (INV-10) through the
// githubapp-exported intersection.
func TestIntersectPermissionsMatrix(t *testing.T) {
	got := IntersectPermissions(
		map[string]string{"contents": "write", "issues": "write", "bogus_key": "admin"},
		map[string]string{"contents": "read", "issues": "write"}, // bogus_key absent + unknown anyway
	)
	if got["contents"] != "read" {
		t.Errorf("contents should be min level read, got %q", got["contents"])
	}
	if got["issues"] != "write" {
		t.Errorf("issues should stay write, got %q", got["issues"])
	}
	if _, ok := got["bogus_key"]; ok {
		t.Errorf("unknown/absent key must be dropped: %v", got)
	}
}

func testClientWithApps(baseURL string, hc *http.Client) *Client {
	ghc := github.NewClient(hc)
	u, _ := url.Parse(baseURL + "/")
	ghc.BaseURL = u
	c := testClient(baseURL, hc)
	c.apps = ghc
	return c
}

func TestValidateAppPermissionsHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"test-app","permissions":{"contents":"write","issues":"write"}}`))
	}))
	defer srv.Close()
	c := testClientWithApps(srv.URL, srv.Client())

	err := c.ValidateAppPermissions(context.Background(), map[string]string{"contents": "read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateAppPermissionsMissingKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"test-app","permissions":{"contents":"read"}}`))
	}))
	defer srv.Close()
	c := testClientWithApps(srv.URL, srv.Client())

	err := c.ValidateAppPermissions(context.Background(), map[string]string{"contents": "read", "issues": "write"})
	if err == nil {
		t.Fatal("expected error for missing permission")
	}
	if !strings.Contains(err.Error(), "issues") {
		t.Errorf("error should mention missing key 'issues': %v", err)
	}
}

func TestValidateAppPermissionsInsufficientLevel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"test-app","permissions":{"contents":"read"}}`))
	}))
	defer srv.Close()
	c := testClientWithApps(srv.URL, srv.Client())

	err := c.ValidateAppPermissions(context.Background(), map[string]string{"contents": "write"})
	if err == nil {
		t.Fatal("expected error for insufficient level")
	}
	if !strings.Contains(err.Error(), "need write, have read") {
		t.Errorf("error should describe level mismatch: %v", err)
	}
}

func TestValidateAppPermissionsEmptyRequired(t *testing.T) {
	c := testClient("http://unused", http.DefaultClient)
	err := c.ValidateAppPermissions(context.Background(), map[string]string{})
	if err != nil {
		t.Fatalf("empty required should pass trivially, got %v", err)
	}
}

func TestValidateAppPermissionsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := testClientWithApps(srv.URL, srv.Client())

	err := c.ValidateAppPermissions(context.Background(), map[string]string{"contents": "read"})
	if err == nil {
		t.Fatal("expected error on API failure")
	}
	if !strings.Contains(err.Error(), "fetch app manifest") {
		t.Errorf("error should wrap API failure: %v", err)
	}
}

func TestPermMapDropsNilFields(t *testing.T) {
	read := "read"
	m := permMap(&github.InstallationPermissions{Contents: &read})
	if m["contents"] != "read" {
		t.Fatalf("permMap round-trip failed: %v", m)
	}
	if len(m) != 1 {
		t.Fatalf("only non-nil fields must survive, got %v", m)
	}
}
