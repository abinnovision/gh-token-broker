package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/abinnovision/gh-token-broker/internal/audit"
	"github.com/abinnovision/gh-token-broker/internal/auth"
	"github.com/abinnovision/gh-token-broker/internal/config"
	"github.com/abinnovision/gh-token-broker/internal/githubapp"
	"github.com/abinnovision/gh-token-broker/internal/policy"
	"github.com/abinnovision/gh-token-broker/internal/server"
)

const testIssuer = "https://issuer.example.com"

type fakeAuth struct {
	id  *auth.Identity
	err error
}

func (f fakeAuth) Authenticate(context.Context, string) (*auth.Identity, error) {
	return f.id, f.err
}

type fakeMinter struct {
	called   bool
	tok      githubapp.ScopedToken
	err      error
	gotOwner string
	gotRepos []string
	gotPerms map[string]string
}

func (f *fakeMinter) Mint(_ context.Context, owner string, repos []string, perms map[string]string) (githubapp.ScopedToken, error) {
	f.called = true
	f.gotOwner = owner
	f.gotRepos = repos
	f.gotPerms = perms
	return f.tok, f.err
}

func acmeIdentity() *auth.Identity {
	return &auth.Identity{
		Repository:      "acme/app",
		RepositoryOwner: "acme",
		JobWorkflowRef:  "acme/app/.github/workflows/ci.yml@refs/heads/main",
	}
}

type harness struct {
	server *server.Server
	minter *fakeMinter
	audit  *bytes.Buffer
}

func newHarness(t *testing.T, policies []config.Policy) harness {
	t.Helper()
	cfg := &config.Config{Policy: config.PolicyConfig{CostLimit: 10000, MaxRepositories: 256, Policies: policies}}
	engine, err := policy.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	minter := &fakeMinter{tok: githubapp.ScopedToken{
		Token:        "ghs_test",
		ExpiresAt:    time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
		Permissions:  map[string]string{"contents": "read"},
		Repositories: []string{"app"},
	}}
	var buf bytes.Buffer
	auditLog := audit.New(slog.New(slog.NewJSONHandler(&buf, nil)))
	srv := server.New(fakeAuth{id: acmeIdentity()}, engine, minter,
		auditLog, slog.New(slog.DiscardHandler), testIssuer)
	return harness{server: srv, minter: minter, audit: &buf}
}

// baseTokenForm returns a valid RFC 8693 token-exchange request form for
// "acme/app" with scope "contents:read"; tests mutate/override as needed.
func baseTokenForm() url.Values {
	return url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {"testtoken"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
		"resource":           {"acme/app"},
		"scope":              {"contents:read"},
	}
}

func doToken(h http.Handler, form url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	return rec
}

func oauthError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %v (body=%s)", err, rec.Body.String())
	}
	code, _ := out["error"].(string)
	if code == "" {
		t.Fatalf("response has no error field: %s", rec.Body.String())
	}
	return code
}

func allowTokenPolicy() config.Policy {
	return config.Policy{
		Name: "allow-acme-token", Condition: `caller.repository_owner == "acme" && request.repositories.all(r, r == "acme/app")`,
		Grant: config.Grant{
			Permissions: map[string]string{"contents": "read"},
		},
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
}

func TestOpenAPISpecServed(t *testing.T) {
	h := newHarness(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	h.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json = %d", rec.Code)
	}
	var spec map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	if spec["openapi"] != "3.1.0" {
		t.Errorf("openapi version = %v", spec["openapi"])
	}
}

func TestMetadataRoute(t *testing.T) {
	h := newHarness(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	h.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["issuer"] != testIssuer {
		t.Errorf("issuer = %v, want %s", out["issuer"], testIssuer)
	}
	if out["token_endpoint"] != testIssuer+"/token" {
		t.Errorf("token_endpoint = %v, want %s/token", out["token_endpoint"], testIssuer)
	}
	grants, _ := out["grant_types_supported"].([]any)
	if len(grants) != 1 || grants[0] != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_types_supported = %v", out["grant_types_supported"])
	}
}

func TestOpenIDConfigurationAliasesMetadata(t *testing.T) {
	h := newHarness(t, nil)

	recAuth := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(recAuth, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	recOIDC := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(recOIDC, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	if recOIDC.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recOIDC.Code, recOIDC.Body.String())
	}
	if recOIDC.Body.String() != recAuth.Body.String() {
		t.Errorf("openid-configuration body = %s, want it to match oauth-authorization-server body %s", recOIDC.Body.String(), recAuth.Body.String())
	}
}

func TestTokenIssued(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	rec := doToken(h.server.Handler(), baseTokenForm())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !h.minter.called {
		t.Fatal("minter should have been called")
	}
	if got := h.minter.gotRepos; len(got) != 1 || got[0] != "acme/app" {
		t.Fatalf("mint repositories = %v, want [acme/app]", got)
	}
	if got := h.minter.gotPerms; len(got) != 1 || got["contents"] != "read" {
		t.Fatalf("mint permissions = %v, want contents:read", got)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["access_token"] != "ghs_test" {
		t.Fatalf("access_token missing in response: %v", out)
	}
	if out["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("issued_token_type = %v", out["issued_token_type"])
	}
	if out["token_type"] != "bearer" {
		t.Errorf("token_type = %v, want bearer", out["token_type"])
	}
	if _, ok := out["expires_in"]; !ok {
		t.Errorf("expires_in missing: %v", out)
	}
	// Granted permissions (contents:read) equal requested scope, so scope
	// should be omitted from the response.
	if _, ok := out["scope"]; ok {
		t.Errorf("scope should be omitted when granted == requested, got %v", out["scope"])
	}
}

func TestTokenConditionAuthorizesDynamicRepositories(t *testing.T) {
	policy := config.Policy{
		Name:      "gitops-suffix",
		Condition: `request.repositories.all(r, r == caller.repository + "-gitops")`,
		Grant:     config.Grant{Permissions: map[string]string{"contents": "read"}},
	}
	h := newHarness(t, []config.Policy{policy})
	form := baseTokenForm()
	form.Set("resource", "acme/app-gitops")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := h.minter.gotRepos; len(got) != 1 || got[0] != "acme/app-gitops" {
		t.Fatalf("gotRepos = %v, want [acme/app-gitops]", got)
	}
}

func TestTokenConditionRejectsUnauthorizedRepositories(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form.Set("resource", "acme/other")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if code := oauthError(t, rec); code != "invalid_grant" {
		t.Errorf("error = %s, want invalid_grant", code)
	}
	if h.minter.called {
		t.Fatal("minter must not be called for a repository the condition rejects")
	}
}

func TestTokenIssuanceRejectsUnknownRequestedPermission(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form.Set("scope", "not_a_permission:read")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_scope" {
		t.Errorf("error = %s, want invalid_scope", code)
	}
	if h.minter.called {
		t.Fatal("minter must not be called for an unknown requested permission")
	}
}

func TestTokenDenyPathNoGitHubCallAndAudited(t *testing.T) {
	// This policy requires owner "other"; the acme caller does not match.
	policy := config.Policy{
		Name: "only-other", Condition: `caller.repository_owner == "other"`,
		Grant: config.Grant{Permissions: map[string]string{"contents": "read"}},
	}
	h := newHarness(t, []config.Policy{policy})
	rec := doToken(h.server.Handler(), baseTokenForm())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_grant" {
		t.Errorf("error = %s, want invalid_grant", code)
	}
	if h.minter.called {
		t.Fatal("no GitHub call on deny")
	}
	assertAuditDecision(t, h.audit, "deny", "token")
}

func TestTokenAuditRecordsSkippedPolicies(t *testing.T) {
	broken := config.Policy{
		Name: "broken-at-runtime", Condition: "1 / 0 == 0",
		Grant: config.Grant{Permissions: map[string]string{"contents": "read"}},
	}
	h := newHarness(t, []config.Policy{broken, allowTokenPolicy()})
	rec := doToken(h.server.Handler(), baseTokenForm())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	assertAuditPolicyFields(t, h.audit, []string{"allow-acme-token"}, []string{"broken-at-runtime"})
}

func TestTokenExchangeRejectsWrongContentType(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"grant_type":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	h.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_request" {
		t.Errorf("error = %s, want invalid_request", code)
	}
}

func TestTokenExchangeMissingGrantType(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form.Del("grant_type")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_request" {
		t.Errorf("error = %s, want invalid_request", code)
	}
}

func TestTokenExchangeRejectsUnsupportedGrantType(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form.Set("grant_type", "client_credentials")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "unsupported_grant_type" {
		t.Errorf("error = %s, want unsupported_grant_type", code)
	}
	if h.minter.called {
		t.Fatal("minter must not be called")
	}
}

func TestTokenExchangeRejectsActorToken(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form.Set("actor_token", "something")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_request" {
		t.Errorf("error = %s, want invalid_request", code)
	}
}

func TestTokenExchangeRejectsMissingSubjectToken(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form.Del("subject_token")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_request" {
		t.Errorf("error = %s, want invalid_request", code)
	}
}

func TestTokenExchangeRejectsWrongSubjectTokenType(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_request" {
		t.Errorf("error = %s, want invalid_request", code)
	}
}

func TestTokenExchangeRejectsUnsupportedRequestedTokenType(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:jwt")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_request" {
		t.Errorf("error = %s, want invalid_request", code)
	}
}

func TestTokenExchangeSubjectTokenVerificationFailureIsInvalidGrant(t *testing.T) {
	cfg := &config.Config{Policy: config.PolicyConfig{CostLimit: 10000, MaxRepositories: 256, Policies: []config.Policy{allowTokenPolicy()}}}
	engine, err := policy.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	minter := &fakeMinter{}
	auditLog := audit.New(slog.New(slog.DiscardHandler))
	srv := server.New(fakeAuth{err: context.DeadlineExceeded}, engine, minter,
		auditLog, slog.New(slog.DiscardHandler), testIssuer)

	rec := doToken(srv.Handler(), baseTokenForm())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_grant" {
		t.Errorf("error = %s, want invalid_grant", code)
	}
	if minter.called {
		t.Fatal("minter must not be called when subject_token verification fails")
	}
}

func TestTokenExchangeRejectsMultiOwnerResource(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form["resource"] = []string{"acme/app", "other/app"}
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_target" {
		t.Errorf("error = %s, want invalid_target", code)
	}
}

func TestTokenExchangeIgnoresMismatchedAudience(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()})
	form := baseTokenForm()
	form.Set("audience", "other")
	rec := doToken(h.server.Handler(), form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !h.minter.called {
		t.Fatal("minter should have been called despite audience not matching resource owner")
	}
}

func TestTokenExchangeEmptyScopeMintErrorIsInvalidGrant(t *testing.T) {
	cfg := &config.Config{Policy: config.PolicyConfig{CostLimit: 10000, MaxRepositories: 256, Policies: []config.Policy{allowTokenPolicy()}}}
	engine, err := policy.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	minter := &fakeMinter{err: githubapp.ErrEmptyScope}
	auditLog := audit.New(slog.New(slog.DiscardHandler))
	srv := server.New(fakeAuth{id: acmeIdentity()}, engine, minter,
		auditLog, slog.New(slog.DiscardHandler), testIssuer)

	rec := doToken(srv.Handler(), baseTokenForm())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := oauthError(t, rec); code != "invalid_grant" {
		t.Errorf("error = %s, want invalid_grant", code)
	}
}

func assertAuditDecision(t *testing.T, buf *bytes.Buffer, decision, operation string) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	for _, line := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		if m["msg"] == "audit" && m["decision"] == decision && m["operation"] == operation {
			return
		}
	}
	t.Fatalf("no audit line with decision=%s operation=%s in: %s", decision, operation, buf.String())
}

func assertAuditPolicyFields(t *testing.T, buf *bytes.Buffer, matched, skipped []string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil || record["msg"] != "audit" {
			continue
		}
		if _, exists := record["matched_rule"]; exists {
			t.Fatalf("legacy matched_rule must not be emitted: %s", line)
		}
		if _, exists := record["matched_policies"]; !exists {
			t.Fatalf("matched_policies must be emitted: %s", line)
		}
		if _, exists := record["skipped_policies"]; !exists {
			t.Fatalf("skipped_policies must be emitted: %s", line)
		}
		if !reflect.DeepEqual(auditStrings(record["matched_policies"]), matched) ||
			!reflect.DeepEqual(auditStrings(record["skipped_policies"]), skipped) {
			t.Fatalf("policy audit fields = matched:%v skipped:%v, want matched:%v skipped:%v",
				record["matched_policies"], record["skipped_policies"], matched, skipped)
		}
		return
	}
	t.Fatalf("no audit line in: %s", buf.String())
}

func auditStrings(value any) []string {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i], _ = value.(string)
	}
	return out
}
