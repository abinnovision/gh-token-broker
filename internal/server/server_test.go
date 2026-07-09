package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abinnovision/gh-token-broker/internal/actions"
	"github.com/abinnovision/gh-token-broker/internal/audit"
	"github.com/abinnovision/gh-token-broker/internal/auth"
	"github.com/abinnovision/gh-token-broker/internal/config"
	"github.com/abinnovision/gh-token-broker/internal/githubapp"
	"github.com/abinnovision/gh-token-broker/internal/policy"
	"github.com/abinnovision/gh-token-broker/internal/server"
)

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

type fakeDispatcher struct {
	called bool
	err    error
}

func (f *fakeDispatcher) Dispatch(context.Context, string, actions.Target) error {
	f.called = true
	return f.err
}

func acmeIdentity() *auth.Identity {
	return &auth.Identity{
		Repository:      "acme/app",
		RepositoryOwner: "acme",
		JobWorkflowRef:  "acme/app/.github/workflows/ci.yml@refs/heads/main",
	}
}

type harness struct {
	server     *server.Server
	minter     *fakeMinter
	dispatcher *fakeDispatcher
	audit      *bytes.Buffer
}

func newHarness(t *testing.T, rules []config.Rule, tokenEnabled bool) harness {
	t.Helper()
	cfg := &config.Config{Policy: config.PolicyConfig{CostLimit: 10000, MaxRepositories: 256, Rules: rules}}
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
	dispatcher := &fakeDispatcher{}
	var buf bytes.Buffer
	auditLog := audit.New(slog.New(slog.NewJSONHandler(&buf, nil)))
	srv := server.New(fakeAuth{id: acmeIdentity()}, engine, minter, dispatcher,
		auditLog, slog.New(slog.DiscardHandler), tokenEnabled)
	return harness{server: srv, minter: minter, dispatcher: dispatcher, audit: &buf}
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer testtoken")
	h.ServeHTTP(rec, req)
	return rec
}

func allowAllRule() config.Rule {
	return config.Rule{
		Name: "allow-acme", When: `caller.repository_owner == "acme"`,
		Grant: config.Grant{
			Repositories: []string{"acme/app"},
			Permissions:  map[string]string{"actions": "write", "contents": "read"},
		},
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, nil, false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
}

func TestOpenAPISpecServed(t *testing.T) {
	h := newHarness(t, nil, false)
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

func TestTokenRouteAbsentWhenDisabled(t *testing.T) {
	h := newHarness(t, []config.Rule{allowAllRule()}, false)
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/app"],"permissions":{"contents":"read"}}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("token route must be absent (404) when disabled, got %d", rec.Code)
	}
	if h.minter.called {
		t.Fatal("minter must not be called")
	}
}

func TestTokenIssuedWhenEnabled(t *testing.T) {
	h := newHarness(t, []config.Rule{allowAllRule()}, true)
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/app"],"permissions":{"contents":"read"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !h.minter.called {
		t.Fatal("minter should have been called")
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["token"] != "ghs_test" {
		t.Fatalf("token missing in response: %v", out)
	}
}

// TestTokenIssuanceNoRepoCeilingPassesThroughRequest locks in that omitting
// grant.repositories is not a ceiling of nothing — it means "when" already
// fully authorized the requested target, so the requested repositories pass
// through unchanged.
func TestTokenIssuanceNoRepoCeilingPassesThroughRequest(t *testing.T) {
	rule := config.Rule{
		Name: "gitops-suffix",
		When: `request.repositories.all(r, r == caller.repository + "-gitops")`,
		Grant: config.Grant{
			// Repositories intentionally omitted.
			Permissions: map[string]string{"contents": "read"},
		},
	}
	h := newHarness(t, []config.Rule{rule}, true)
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/app-gitops"],"permissions":{"contents":"read"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := h.minter.gotRepos; len(got) != 1 || got[0] != "acme/app-gitops" {
		t.Fatalf("gotRepos = %v, want [acme/app-gitops]", got)
	}
}

// TestTokenIssuanceStillNarrowsWithDeclaredCeiling locks in that a declared
// grant.repositories still downscopes a request that asks for more than the
// ceiling allows.
func TestTokenIssuanceStillNarrowsWithDeclaredCeiling(t *testing.T) {
	h := newHarness(t, []config.Rule{allowAllRule()}, true) // ceiling: ["acme/app"]
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/app","acme/other"],"permissions":{"contents":"read"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := h.minter.gotRepos; len(got) != 1 || got[0] != "acme/app" {
		t.Fatalf("gotRepos = %v, want [acme/app] (acme/other must be narrowed out)", got)
	}
}

func TestTokenDenyPathNoGitHubCallAndAudited(t *testing.T) {
	// Rule requires owner "other"; acme caller does not match → deny.
	rule := config.Rule{
		Name: "only-other", When: `caller.repository_owner == "other"`,
		Grant: config.Grant{Repositories: []string{"other/x"}, Permissions: map[string]string{"contents": "read"}},
	}
	h := newHarness(t, []config.Rule{rule}, true)
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/app"],"permissions":{"contents":"read"}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if h.minter.called {
		t.Fatal("no GitHub call on deny")
	}
	assertAuditDecision(t, h.audit, "deny", "token")
}

func TestWorkflowDispatchHappyPath(t *testing.T) {
	h := newHarness(t, []config.Rule{allowAllRule()}, false)
	rec := do(h.server.Handler(), http.MethodPost, "/actions/workflow-dispatch",
		`{"owner":"acme","repo":"app","ref":"refs/heads/main","workflow":"ci.yml"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !h.minter.called || !h.dispatcher.called {
		t.Fatalf("minter=%v dispatcher=%v, both should fire", h.minter.called, h.dispatcher.called)
	}
	assertAuditDecision(t, h.audit, "allow", "workflow-dispatch")
}

// TestWorkflowDispatchNoRepoCeilingUsesTarget mirrors the token-issuance case
// for the dispatch endpoint: an omitted grant.repositories means the
// dispatched target itself is the granted repo, not "nothing".
func TestWorkflowDispatchNoRepoCeilingUsesTarget(t *testing.T) {
	rule := config.Rule{
		Name: "gitops-suffix",
		When: `(action.owner + "/" + action.repo) == caller.repository + "-gitops"`,
		Grant: config.Grant{
			// Repositories intentionally omitted.
			Permissions: map[string]string{"actions": "write"},
		},
	}
	h := newHarness(t, []config.Rule{rule}, false)
	rec := do(h.server.Handler(), http.MethodPost, "/actions/workflow-dispatch",
		`{"owner":"acme","repo":"app-gitops","ref":"refs/heads/main","workflow":"ci.yml"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := h.minter.gotRepos; len(got) != 1 || got[0] != "acme/app-gitops" {
		t.Fatalf("gotRepos = %v, want [acme/app-gitops]", got)
	}
}

// TestWorkflowDispatchDeniesWhenGrantDoesNotCoverRequiredPermission locks in
// that a rule granting the "actions" permission at too low a level (or a
// different permission entirely) is caught as a policy denial, not left to
// fail later as an opaque GitHub API rejection.
func TestWorkflowDispatchDeniesWhenGrantDoesNotCoverRequiredPermission(t *testing.T) {
	rule := config.Rule{
		Name: "insufficient-level",
		When: `caller.repository_owner == "acme"`,
		Grant: config.Grant{
			Repositories: []string{"acme/app"},
			Permissions:  map[string]string{"actions": "read"}, // dispatch needs write
		},
	}
	h := newHarness(t, []config.Rule{rule}, false)
	rec := do(h.server.Handler(), http.MethodPost, "/actions/workflow-dispatch",
		`{"owner":"acme","repo":"app","ref":"refs/heads/main","workflow":"ci.yml"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if h.minter.called || h.dispatcher.called {
		t.Fatal("no mint/dispatch when the grant doesn't cover the required permission level")
	}
	assertAuditDecision(t, h.audit, "deny", "workflow-dispatch")
}

func TestWorkflowDispatchRejectsScopeFields(t *testing.T) {
	h := newHarness(t, []config.Rule{allowAllRule()}, false)
	rec := do(h.server.Handler(), http.MethodPost, "/actions/workflow-dispatch",
		`{"owner":"acme","repo":"app","ref":"refs/heads/main","workflow":"ci.yml","permissions":{"contents":"admin"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (scope fields forbidden on workflow-dispatch)", rec.Code)
	}
	if h.minter.called {
		t.Fatal("minter must not be called when the request is rejected")
	}
}

func TestWorkflowDispatchDenyNoDispatch(t *testing.T) {
	rule := config.Rule{
		Name: "only-other", When: `caller.repository_owner == "other"`,
		Grant: config.Grant{Repositories: []string{"other/x"}, Permissions: map[string]string{"actions": "write"}},
	}
	h := newHarness(t, []config.Rule{rule}, false)
	rec := do(h.server.Handler(), http.MethodPost, "/actions/workflow-dispatch",
		`{"owner":"acme","repo":"app","ref":"refs/heads/main","workflow":"ci.yml"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if h.minter.called || h.dispatcher.called {
		t.Fatal("no mint/dispatch on deny")
	}
	assertAuditDecision(t, h.audit, "deny", "workflow-dispatch")
}

func TestMissingBearerIs401(t *testing.T) {
	h := newHarness(t, []config.Rule{allowAllRule()}, false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/actions/workflow-dispatch",
		strings.NewReader(`{"owner":"acme","repo":"app","ref":"main","workflow":"ci.yml"}`))
	// No Authorization header.
	h.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
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
