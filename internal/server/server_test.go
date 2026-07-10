package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func newHarness(t *testing.T, policies []config.Policy, tokenEnabled bool) harness {
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

func allowTokenPolicy() config.Policy {
	return config.Policy{
		Name: "allow-acme-token", Condition: `caller.repository_owner == "acme" && request.repositories.all(r, r == "acme/app")`,
		Grant: config.Grant{
			Permissions: map[string]string{"contents": "read"},
		},
	}
}

func allowDispatchPolicy() config.Policy {
	return config.Policy{
		Name: "allow-acme-dispatch", Condition: `request.?workflow_dispatch.hasValue() && caller.repository_owner == "acme" && request.workflow_dispatch.owner == "acme" && request.workflow_dispatch.repo == "app"`,
		Grant: config.Grant{
			Permissions: map[string]string{"actions": "write", "contents": "read"},
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
	h := newHarness(t, []config.Policy{allowTokenPolicy()}, false)
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
	h := newHarness(t, []config.Policy{allowTokenPolicy()}, true)
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/app"],"permissions":{"contents":"read"}}`)
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
	if out["token"] != "ghs_test" {
		t.Fatalf("token missing in response: %v", out)
	}
}

func TestTokenConditionAuthorizesDynamicRepositories(t *testing.T) {
	policy := config.Policy{
		Name:      "gitops-suffix",
		Condition: `request.repositories.all(r, r == caller.repository + "-gitops")`,
		Grant:     config.Grant{Permissions: map[string]string{"contents": "read"}},
	}
	h := newHarness(t, []config.Policy{policy}, true)
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/app-gitops"],"permissions":{"contents":"read"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := h.minter.gotRepos; len(got) != 1 || got[0] != "acme/app-gitops" {
		t.Fatalf("gotRepos = %v, want [acme/app-gitops]", got)
	}
}

func TestTokenConditionRejectsUnauthorizedRepositories(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()}, true)
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/other"],"permissions":{"contents":"read"}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if h.minter.called {
		t.Fatal("minter must not be called for a repository the condition rejects")
	}
}

func TestTokenIssuanceRejectsUnknownRequestedPermission(t *testing.T) {
	h := newHarness(t, []config.Policy{allowTokenPolicy()}, true)
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/app"],"permissions":{"not_a_permission":"read"}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
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
	h := newHarness(t, []config.Policy{policy}, true)
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

func TestTokenAuditRecordsSkippedPolicies(t *testing.T) {
	broken := config.Policy{
		Name: "broken-at-runtime", Condition: "1 / 0 == 0",
		Grant: config.Grant{Permissions: map[string]string{"contents": "read"}},
	}
	h := newHarness(t, []config.Policy{broken, allowTokenPolicy()}, true)
	rec := do(h.server.Handler(), http.MethodPost, "/token",
		`{"repositories":["acme/app"],"permissions":{"contents":"read"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	assertAuditPolicyFields(t, h.audit, []string{"allow-acme-token"}, []string{"broken-at-runtime"})
}

func TestWorkflowDispatchHappyPath(t *testing.T) {
	h := newHarness(t, []config.Policy{allowDispatchPolicy()}, false)
	rec := do(h.server.Handler(), http.MethodPost, "/actions/workflow-dispatch",
		`{"owner":"acme","repo":"app","ref":"refs/heads/main","workflow":"ci.yml"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !h.minter.called || !h.dispatcher.called {
		t.Fatalf("minter=%v dispatcher=%v, both should fire", h.minter.called, h.dispatcher.called)
	}
	assertAuditDecision(t, h.audit, "allow", "workflow-dispatch")
	assertAuditPolicyFields(t, h.audit, []string{"allow-acme-dispatch"}, nil)
}

func TestWorkflowConditionAuthorizesDynamicTarget(t *testing.T) {
	policy := config.Policy{
		Name:      "gitops-suffix",
		Condition: `request.?workflow_dispatch.hasValue() && (request.workflow_dispatch.owner + "/" + request.workflow_dispatch.repo) == caller.repository + "-gitops"`,
		Grant:     config.Grant{Permissions: map[string]string{"actions": "write"}},
	}
	h := newHarness(t, []config.Policy{policy}, false)
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
// that a policy granting the "actions" permission at too low a level (or a
// different permission entirely) is caught as a policy denial, not left to
// fail later as an opaque GitHub API rejection.
func TestWorkflowDispatchDeniesWhenGrantDoesNotCoverRequiredPermission(t *testing.T) {
	policy := config.Policy{
		Name:      "insufficient-level",
		Condition: `request.?workflow_dispatch.hasValue() && caller.repository_owner == "acme" && request.workflow_dispatch.owner == "acme" && request.workflow_dispatch.repo == "app"`,
		Grant: config.Grant{
			Permissions: map[string]string{"actions": "read"}, // dispatch needs write
		},
	}
	h := newHarness(t, []config.Policy{policy}, false)
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
	h := newHarness(t, []config.Policy{allowDispatchPolicy()}, false)
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
	policy := config.Policy{
		Name: "only-other", Condition: `caller.repository_owner == "other"`,
		Grant: config.Grant{Permissions: map[string]string{"actions": "write"}},
	}
	h := newHarness(t, []config.Policy{policy}, false)
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
	h := newHarness(t, []config.Policy{allowDispatchPolicy()}, false)
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
