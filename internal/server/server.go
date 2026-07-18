// Package server exposes the HTTP API: an RFC 8693 OAuth 2.0 Token Exchange
// endpoint at /token, its metadata document (served under both the RFC 8414
// and OpenID Connect Discovery well-known paths), healthz, and the OpenAPI
// spec.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"

	githubappproxy "github.com/abinnovision/gh-token-broker"
	"github.com/abinnovision/gh-token-broker/internal/audit"
	"github.com/abinnovision/gh-token-broker/internal/auth"
	"github.com/abinnovision/gh-token-broker/internal/githubapp"
	"github.com/abinnovision/gh-token-broker/internal/perm"
	"github.com/abinnovision/gh-token-broker/internal/policy"
)

const maxBodyBytes = 1 << 20

// RFC 8693 / RFC 6749 grant, token-type and error identifiers.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // G101: RFC 8693 grant-type URN, not a credential
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"   //nolint:gosec // G101: RFC 8693 token-type URN, not a credential
	tokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"       //nolint:gosec // G101: RFC 8693 token-type URN, not a credential

	errInvalidRequest   = "invalid_request"
	errUnsupportedGrant = "unsupported_grant_type"
	errInvalidGrant     = "invalid_grant"
	errInvalidScope     = "invalid_scope"
	errInvalidTarget    = "invalid_target"
	errServerError      = "server_error"
)

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
	auth         Authenticator
	engine       *policy.Engine
	minter       Minter
	audit        *audit.Logger
	logger       *slog.Logger
	issuer       string
	metadataJSON []byte
}

// New constructs a Server. issuer is the broker's own OAuth issuer
// identifier (an absolute https:// URL); it is used verbatim in RFC 8414
// metadata.
func New(
	authn Authenticator,
	engine *policy.Engine,
	minter Minter,
	auditLog *audit.Logger,
	logger *slog.Logger,
	issuer string,
) *Server {
	s := &Server{
		auth:   authn,
		engine: engine,
		minter: minter,
		audit:  auditLog,
		logger: logger,
		issuer: issuer,
	}
	s.metadataJSON = buildMetadataJSON(issuer)
	return s
}

// buildMetadataJSON precomputes the RFC 8414 authorization-server metadata
// document once at construction time.
func buildMetadataJSON(issuer string) []byte {
	body, err := json.Marshal(map[string]any{
		"issuer":                                issuer,
		"token_endpoint":                        issuer + "/token",
		"grant_types_supported":                 []string{grantTypeTokenExchange},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
	if err != nil {
		// Marshaling a map of strings/[]string never fails.
		panic(err)
	}
	return body
}

// Handler builds the mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleMetadata)
	// Also served under the OIDC Discovery path so RFC-8693 clients that
	// only know how to discover via OpenID Connect Discovery (e.g.
	// oidc-token-cli) can find the token endpoint too.
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleMetadata)
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

func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.metadataJSON)
}

// --- token exchange (RFC 8693) -------------------------------------------------

// tokenExchangeResponse is the RFC 6749 §5.1 / RFC 8693 §2.2.1 token-endpoint
// success response.
type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	// TokenType is "bearer": GitHub installation tokens ARE used as ordinary
	// bearer credentials against GitHub's API, so this is not the "N_A" case
	// RFC 8693 §2.2.1 describes for non-bearer-usable issued tokens.
	TokenType string `json:"token_type"`
	ExpiresIn int64  `json:"expires_in"`
	Scope     string `json:"scope,omitempty"`
}

// oauthErrorResponse is the RFC 6749 §5.2 token-endpoint error response.
type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, oauthErrorResponse{Error: code, ErrorDescription: description})
}

// handleToken implements the RFC 8693 OAuth 2.0 Token Exchange grant, and
// only that grant: any other grant_type is rejected outright.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "malformed request body")
		return
	}
	form := r.PostForm

	grantType := form.Get("grant_type")
	if grantType == "" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "grant_type is required")
		return
	}
	if grantType != grantTypeTokenExchange {
		writeOAuthError(w, http.StatusBadRequest, errUnsupportedGrant, "only "+grantTypeTokenExchange+" is supported")
		return
	}
	if form.Get("actor_token") != "" || form.Get("actor_token_type") != "" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "actor_token delegation is not supported")
		return
	}

	subjectToken := form.Get("subject_token")
	subjectTokenType := form.Get("subject_token_type")
	if subjectToken == "" || subjectTokenType == "" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "subject_token and subject_token_type are required")
		return
	}
	if subjectTokenType != tokenTypeIDToken {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "subject_token_type must be "+tokenTypeIDToken)
		return
	}

	if requestedType := form.Get("requested_token_type"); requestedType != "" && requestedType != tokenTypeAccessToken {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "requested_token_type must be "+tokenTypeAccessToken)
		return
	}

	id, err := s.auth.Authenticate(r.Context(), subjectToken)
	if err != nil {
		s.logger.Warn("authentication failed", "error", err.Error())
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "subject_token verification failed")
		return
	}

	repositories := form["resource"]
	if len(repositories) == 0 {
		writeOAuthError(w, http.StatusBadRequest, errInvalidTarget, "resource is required (one owner/repo value per repository)")
		return
	}
	owner, ok := singleOwner(repositories)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, errInvalidTarget, "all resource values must be owner/repo and share one owner")
		return
	}
	// audience, if present, is not validated against owner: resource is the
	// sole source of truth for the target scope, and RFC 8693 does not
	// require audience to match it. Some clients (e.g. oidc-token-cli) reuse
	// their subject-token audience for this parameter, which need not equal
	// the resource owner.

	perms, ok := decodeScope(form.Get("scope"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, errInvalidScope, "scope must be a space-delimited list of permission:level tokens")
		return
	}

	decision, err := s.engine.Evaluate(policy.Input{
		Caller:  policyCaller(id),
		Request: policy.Request{Repositories: repositories},
	}, policy.Scope{Permissions: perms})
	if err != nil {
		// Oversized request.repositories is rejected, not truncated.
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, err.Error())
		return
	}
	if !decision.Allowed {
		s.auditDeny("token", id, decision, denyReason(decision))
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "forbidden by policy")
		return
	}

	token, err := s.minter.Mint(r.Context(), owner, repositories, perms)
	if err != nil {
		if errors.Is(err, githubapp.ErrEmptyScope) {
			s.auditDeny("token", id, decision, "empty computed scope")
			writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "forbidden by policy")
			return
		}
		if errors.Is(err, githubapp.ErrInsufficientScope) {
			s.auditDeny("token", id, decision, "installation permissions insufficient")
			writeOAuthError(w, http.StatusBadRequest, errInvalidScope, "requested scope exceeds installation permissions")
			return
		}
		s.logger.Error("mint token", "error", err.Error())
		writeOAuthError(w, http.StatusBadGateway, errServerError, "upstream error")
		return
	}

	s.audit.Log(audit.Event{
		Operation:       "token",
		Decision:        audit.DecisionAllow,
		Caller:          id.PolicyClaims(),
		MatchedPolicies: decision.MatchedPolicies,
		SkippedPolicies: decision.SkippedPolicies,
		RequestedScope:  map[string]any{"repositories": repositories, "permissions": perms},
		ComputedScope:   map[string]any{"repositories": token.Repositories, "permissions": token.Permissions},
		TokenIssued:     true,
	})

	resp := tokenExchangeResponse{
		AccessToken:     token.Token,
		IssuedTokenType: tokenTypeAccessToken,
		TokenType:       "bearer",
		ExpiresIn:       int64(time.Until(token.ExpiresAt).Seconds()),
	}
	if !scopeEqual(perms, token.Permissions) {
		resp.Scope = encodeScope(token.Permissions)
	}
	writeJSON(w, http.StatusOK, resp)
}

// decodeScope parses an RFC 8693 space-delimited scope string of
// "permission:level" tokens into the internal permission-map shape. Unlike
// perm.Normalize (which silently drops unknown entries), any invalid token
// fails the whole scope — a token-exchange request with a malformed scope is
// a client error, not a partial grant.
func decodeScope(scope string) (map[string]string, bool) {
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		return nil, false
	}
	perms := make(map[string]string, len(fields))
	for _, tok := range fields {
		idx := strings.LastIndex(tok, ":")
		if idx <= 0 || idx == len(tok)-1 {
			return nil, false
		}
		key, level := tok[:idx], tok[idx+1:]
		if !perm.ValidKey(key) || !perm.ValidLevel(level) {
			return nil, false
		}
		perms[key] = level
	}
	return perms, true
}

// encodeScope is the inverse of decodeScope, with keys sorted for
// deterministic output.
func encodeScope(perms map[string]string) string {
	keys := make([]string, 0, len(perms))
	for k := range perms {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tokens := make([]string, 0, len(keys))
	for _, k := range keys {
		tokens = append(tokens, k+":"+perms[k])
	}
	return strings.Join(tokens, " ")
}

func scopeEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
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
