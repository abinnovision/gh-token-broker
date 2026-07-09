// Package server exposes the proxy's HTTP API: A2 workflow-dispatch (always
// on), A1 token issuance (registered only when enabled), and healthz. Both A1
// and A2 route through the same policy evaluation and the same githubapp
// minting chokepoint.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/abinnovision/gh-token-broker/internal/actions"
	"github.com/abinnovision/gh-token-broker/internal/audit"
	"github.com/abinnovision/gh-token-broker/internal/auth"
	"github.com/abinnovision/gh-token-broker/internal/config"
	"github.com/abinnovision/gh-token-broker/internal/githubapp"
	"github.com/abinnovision/gh-token-broker/internal/perm"
	"github.com/abinnovision/gh-token-broker/internal/policy"
)

const maxBodyBytes = 1 << 20

// Authenticator verifies a bearer token into a caller Identity.
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (*auth.Identity, error)
}

// Minter resolves the installation for owner and mints a scoped token for the
// given repositories and permissions. Implemented by *githubapp.Client.
type Minter interface {
	Mint(ctx context.Context, owner string, repos []string, perms map[string]string) (githubapp.ScopedToken, error)
}

// Server holds the wired dependencies for the HTTP handlers.
type Server struct {
	auth                 Authenticator
	engine               *policy.Engine
	minter               Minter
	dispatcher           actions.Dispatcher
	actions              map[string]config.ActionConfig
	audit                *audit.Logger
	logger               *slog.Logger
	tokenIssuanceEnabled bool
}

// New constructs a Server.
func New(
	authn Authenticator,
	engine *policy.Engine,
	minter Minter,
	dispatcher actions.Dispatcher,
	actionsCfg map[string]config.ActionConfig,
	auditLog *audit.Logger,
	logger *slog.Logger,
	tokenIssuanceEnabled bool,
) *Server {
	return &Server{
		auth:                 authn,
		engine:               engine,
		minter:               minter,
		dispatcher:           dispatcher,
		actions:              actionsCfg,
		audit:                auditLog,
		logger:               logger,
		tokenIssuanceEnabled: tokenIssuanceEnabled,
	}
}

// Handler builds the mux. The /token route is registered ONLY when token
// issuance is enabled — when disabled it is absent from the router entirely,
// not merely a 403, keeping the safe default footprint smaller.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /actions/workflow-dispatch", s.handleWorkflowDispatch)
	if s.tokenIssuanceEnabled {
		mux.HandleFunc("POST /token", s.handleToken)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// authenticate extracts and verifies the bearer token, writing a 401 on
// failure.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	authz := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok || token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return nil, false
	}
	id, err := s.auth.Authenticate(r.Context(), token)
	if err != nil {
		s.logger.Warn("authentication failed", "error", err.Error())
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return id, true
}

// --- A2: workflow-dispatch ---------------------------------------------------

type dispatchRequest struct {
	Owner    string         `json:"owner"`
	Repo     string         `json:"repo"`
	Ref      string         `json:"ref"`
	Workflow string         `json:"workflow"`
	Inputs   map[string]any `json:"inputs"`
	// Scope-looking fields are forbidden on A2 (INV-6). Their presence is a
	// caller error and rejected outright.
	Permissions  json.RawMessage `json:"permissions"`
	Repositories json.RawMessage `json:"repositories"`
}

func (s *Server) handleWorkflowDispatch(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req dispatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}
	if req.Permissions != nil || req.Repositories != nil {
		http.Error(w, "workflow-dispatch requests must not carry permissions or repositories fields", http.StatusBadRequest)
		return
	}
	if req.Owner == "" || req.Repo == "" || req.Workflow == "" || req.Ref == "" {
		http.Error(w, "owner, repo, workflow and ref are required", http.StatusBadRequest)
		return
	}

	actionCfg, ok := s.actions[actions.WorkflowDispatch]
	if !ok {
		s.logger.Error("workflow-dispatch action not configured")
		http.Error(w, "workflow-dispatch action not configured", http.StatusInternalServerError)
		return
	}

	target := req.Owner + "/" + req.Repo
	decision, err := s.engine.Evaluate(policy.Input{
		Caller:   id.PolicyClaims(),
		Advisory: id.AdvisoryClaims(),
		Action: map[string]any{
			"name":     actions.WorkflowDispatch,
			"owner":    req.Owner,
			"repo":     req.Repo,
			"ref":      req.Ref,
			"workflow": req.Workflow,
			"inputs":   req.Inputs,
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !decision.Matched {
		s.auditDeny("workflow-dispatch", id, decision.RuleName, "no matching allow rule")
		http.Error(w, "forbidden by policy", http.StatusForbidden)
		return
	}

	finalRepos := intersectRepos([]string{target}, decision.Grant.Repositories)
	finalPerms := perm.Intersect(actionCfg.Permissions, decision.Grant.Permissions)
	if len(finalRepos) == 0 || len(finalPerms) == 0 {
		s.auditDeny("workflow-dispatch", id, decision.RuleName, "policy narrowed scope to empty")
		http.Error(w, "forbidden by policy", http.StatusForbidden)
		return
	}

	token, err := s.minter.Mint(r.Context(), req.Owner, finalRepos, finalPerms)
	if err != nil {
		if errors.Is(err, githubapp.ErrEmptyScope) {
			s.auditDeny("workflow-dispatch", id, decision.RuleName, "empty computed scope")
			http.Error(w, "forbidden by policy", http.StatusForbidden)
			return
		}
		s.logger.Error("mint token", "error", err.Error())
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	if err := s.dispatcher.Dispatch(r.Context(), token.Token, actions.Target{
		Owner: req.Owner, Repo: req.Repo, Ref: req.Ref, Workflow: req.Workflow, Inputs: req.Inputs,
	}); err != nil {
		s.logger.Error("dispatch", "error", err.Error())
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	s.audit.Log(audit.Event{
		Operation:     "workflow-dispatch",
		Decision:      audit.DecisionAllow,
		Caller:        id.PolicyClaims(),
		MatchedRule:   decision.RuleName,
		ComputedScope: map[string]any{"repositories": token.Repositories, "permissions": token.Permissions},
		TokenIssued:   false, // A2 never returns the token to the caller
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "dispatched",
		"repository":  target,
		"workflow":    req.Workflow,
		"ref":         req.Ref,
		"permissions": token.Permissions,
	})
}

// --- A1: token issuance (gated) ----------------------------------------------

type tokenRequestBody struct {
	Repositories []string          `json:"repositories"`
	Permissions  map[string]string `json:"permissions"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req tokenRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}
	// A1 requires a non-empty request; an empty request has nothing to issue.
	if len(req.Repositories) == 0 || len(req.Permissions) == 0 {
		http.Error(w, "repositories and permissions are required", http.StatusBadRequest)
		return
	}

	decision, err := s.engine.Evaluate(policy.Input{
		Caller:   id.PolicyClaims(),
		Advisory: id.AdvisoryClaims(),
		Request: map[string]any{
			"repositories": req.Repositories,
			"permissions":  toAnyMap(req.Permissions),
		},
	})
	if err != nil {
		// Oversized request.repositories (INV-7) is rejected, not truncated.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !decision.Matched {
		s.auditDeny("token", id, decision.RuleName, "no matching allow rule")
		http.Error(w, "forbidden by policy", http.StatusForbidden)
		return
	}

	finalRepos := intersectRepos(req.Repositories, decision.Grant.Repositories)
	finalPerms := perm.Intersect(req.Permissions, decision.Grant.Permissions)
	// The request was non-empty; if narrowing produced an empty result, deny
	// rather than escalate (INV-1 at the semantic layer).
	if len(finalRepos) == 0 || len(finalPerms) == 0 {
		s.auditDeny("token", id, decision.RuleName, "policy narrowed scope to empty")
		http.Error(w, "forbidden by policy", http.StatusForbidden)
		return
	}

	owner, ok := singleOwner(finalRepos)
	if !ok {
		http.Error(w, "all repositories must share one owner", http.StatusBadRequest)
		return
	}

	token, err := s.minter.Mint(r.Context(), owner, finalRepos, finalPerms)
	if err != nil {
		if errors.Is(err, githubapp.ErrEmptyScope) {
			s.auditDeny("token", id, decision.RuleName, "empty computed scope")
			http.Error(w, "forbidden by policy", http.StatusForbidden)
			return
		}
		s.logger.Error("mint token", "error", err.Error())
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	s.audit.Log(audit.Event{
		Operation:      "token",
		Decision:       audit.DecisionAllow,
		Caller:         id.PolicyClaims(),
		MatchedRule:    decision.RuleName,
		RequestedScope: map[string]any{"repositories": req.Repositories, "permissions": req.Permissions},
		ComputedScope:  map[string]any{"repositories": token.Repositories, "permissions": token.Permissions},
		TokenIssued:    true,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token.Token,
		"expires_at":   token.ExpiresAt.Format(time.RFC3339),
		"permissions":  token.Permissions,
		"repositories": token.Repositories,
	})
}

// --- helpers -----------------------------------------------------------------

func (s *Server) auditDeny(op string, id *auth.Identity, rule, reason string) {
	matched := rule
	if matched == "" {
		matched = "no rule matched"
	}
	s.audit.Log(audit.Event{
		Operation:   op,
		Decision:    audit.DecisionDeny,
		Caller:      id.PolicyClaims(),
		MatchedRule: matched,
		Reason:      reason,
		TokenIssued: false,
	})
}

// intersectRepos returns the exact-match (anchored, INV-9) set intersection of
// want and allowed, preserving want's order.
func intersectRepos(want, allowed []string) []string {
	allow := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allow[a] = true
	}
	var out []string
	for _, w := range want {
		if allow[w] {
			out = append(out, w)
		}
	}
	return out
}

func singleOwner(repos []string) (string, bool) {
	owner := ""
	for _, full := range repos {
		parts := strings.SplitN(full, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", false
		}
		if owner == "" {
			owner = parts[0]
		} else if owner != parts[0] {
			return "", false
		}
	}
	if owner == "" {
		return "", false
	}
	return owner, true
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
