// Package server exposes the HTTP API: workflow-dispatch (always on), token
// issuance (registered only when enabled), and healthz. Both routes go
// through the same policy evaluation and the same token-minting chokepoint.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	githubappproxy "github.com/abinnovision/gh-token-broker"
	"github.com/abinnovision/gh-token-broker/internal/actions"
	"github.com/abinnovision/gh-token-broker/internal/audit"
	"github.com/abinnovision/gh-token-broker/internal/auth"
	"github.com/abinnovision/gh-token-broker/internal/githubapp"
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
	auditLog *audit.Logger,
	logger *slog.Logger,
	tokenIssuanceEnabled bool,
) *Server {
	return &Server{
		auth:                 authn,
		engine:               engine,
		minter:               minter,
		dispatcher:           dispatcher,
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
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(githubappproxy.OpenAPISpec)
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

// --- workflow-dispatch --------------------------------------------------------

type dispatchRequest struct {
	Owner    string         `json:"owner"`
	Repo     string         `json:"repo"`
	Ref      string         `json:"ref"`
	Workflow string         `json:"workflow"`
	Inputs   map[string]any `json:"inputs"`
	// Scope-looking fields are forbidden here — their presence is a caller
	// error and rejected outright.
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

	requiredPerms := actions.RequiredPermissions[actions.WorkflowDispatch]

	target := req.Owner + "/" + req.Repo
	decision, err := s.engine.Evaluate(policy.Input{
		Caller: policyCaller(id),
		Request: policy.Request{
			Repositories: []string{target},
			WorkflowDispatch: &policy.WorkflowDispatch{
				Owner:    req.Owner,
				Repo:     req.Repo,
				Ref:      req.Ref,
				Workflow: req.Workflow,
			},
		},
	}, policy.Scope{Permissions: requiredPerms})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !decision.Allowed {
		s.auditDeny("workflow-dispatch", id, decision, denyReason(decision))
		http.Error(w, "forbidden by policy", http.StatusForbidden)
		return
	}

	token, err := s.minter.Mint(r.Context(), req.Owner, []string{target}, requiredPerms)
	if err != nil {
		if errors.Is(err, githubapp.ErrEmptyScope) {
			s.auditDeny("workflow-dispatch", id, decision, "empty computed scope")
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
		Operation:       "workflow-dispatch",
		Decision:        audit.DecisionAllow,
		Caller:          id.PolicyClaims(),
		MatchedPolicies: decision.MatchedPolicies,
		SkippedPolicies: decision.SkippedPolicies,
		ComputedScope:   map[string]any{"repositories": token.Repositories, "permissions": token.Permissions},
		TokenIssued:     false, // this endpoint never returns the token to the caller
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "dispatched",
		"repository":  target,
		"workflow":    req.Workflow,
		"ref":         req.Ref,
		"permissions": token.Permissions,
	})
}

// --- token issuance (gated) ---------------------------------------------------

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
	// A non-empty request is required; an empty request has nothing to issue.
	if len(req.Repositories) == 0 || len(req.Permissions) == 0 {
		http.Error(w, "repositories and permissions are required", http.StatusBadRequest)
		return
	}

	decision, err := s.engine.Evaluate(policy.Input{
		Caller:  policyCaller(id),
		Request: policy.Request{Repositories: req.Repositories},
	}, policy.Scope{Permissions: req.Permissions})
	if err != nil {
		// Oversized request.repositories is rejected, not truncated.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !decision.Allowed {
		s.auditDeny("token", id, decision, denyReason(decision))
		http.Error(w, "forbidden by policy", http.StatusForbidden)
		return
	}

	owner, ok := singleOwner(req.Repositories)
	if !ok {
		http.Error(w, "all repositories must share one owner", http.StatusBadRequest)
		return
	}

	token, err := s.minter.Mint(r.Context(), owner, req.Repositories, req.Permissions)
	if err != nil {
		if errors.Is(err, githubapp.ErrEmptyScope) {
			s.auditDeny("token", id, decision, "empty computed scope")
			http.Error(w, "forbidden by policy", http.StatusForbidden)
			return
		}
		s.logger.Error("mint token", "error", err.Error())
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	s.audit.Log(audit.Event{
		Operation:       "token",
		Decision:        audit.DecisionAllow,
		Caller:          id.PolicyClaims(),
		MatchedPolicies: decision.MatchedPolicies,
		SkippedPolicies: decision.SkippedPolicies,
		RequestedScope:  map[string]any{"repositories": req.Repositories, "permissions": req.Permissions},
		ComputedScope:   map[string]any{"repositories": token.Repositories, "permissions": token.Permissions},
		TokenIssued:     true,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token.Token,
		"expires_at":   token.ExpiresAt.Format(time.RFC3339),
		"permissions":  token.Permissions,
		"repositories": token.Repositories,
	})
}

// --- helpers -----------------------------------------------------------------

func (s *Server) auditDeny(op string, id *auth.Identity, decision policy.Decision, reason string) {
	s.audit.Log(audit.Event{
		Operation:       op,
		Decision:        audit.DecisionDeny,
		Caller:          id.PolicyClaims(),
		MatchedPolicies: decision.MatchedPolicies,
		SkippedPolicies: decision.SkippedPolicies,
		Reason:          reason,
		TokenIssued:     false,
	})
}

func denyReason(decision policy.Decision) string {
	if len(decision.MatchedPolicies) == 0 {
		return "no matching policies"
	}
	return "combined policy permissions do not cover requested scope"
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

func policyCaller(id *auth.Identity) policy.Caller {
	return policy.Caller{
		Repository:        id.Repository,
		RepositoryID:      id.RepositoryID,
		RepositoryOwner:   id.RepositoryOwner,
		RepositoryOwnerID: id.RepositoryOwnerID,
		JobWorkflowRef:    id.JobWorkflowRef,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
