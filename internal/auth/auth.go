// Package auth verifies GitHub Actions OIDC bearer tokens and extracts the
// id-anchored claims that policy is allowed to trust. It is the only caller
// authentication method — there is no API-key path.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ExpectedAlg is the only signing algorithm accepted from GitHub's OIDC
// provider. Pinning it rejects alg=none and RS/HS confusion (INV-5).
const ExpectedAlg = "RS256"

// Identity holds the verified, id-anchored claims from a GitHub Actions OIDC
// token that may be used in policy evaluation.
type Identity struct {
	Repository        string
	RepositoryID      string
	RepositoryOwner   string
	RepositoryOwnerID string
	JobWorkflowRef    string // full string including the ref suffix
}

// PolicyClaims returns the verified claims in the audit-log representation.
func (id Identity) PolicyClaims() map[string]string {
	return map[string]string{
		"repository":          id.Repository,
		"repository_id":       id.RepositoryID,
		"repository_owner":    id.RepositoryOwner,
		"repository_owner_id": id.RepositoryOwnerID,
		"job_workflow_ref":    id.JobWorkflowRef,
	}
}

// claims mirrors the subset of the GitHub Actions OIDC token we consume.
type claims struct {
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
	Exp               int64  `json:"exp"`
	Iat               int64  `json:"iat"`
	Nbf               int64  `json:"nbf"`
}

// Authenticator verifies OIDC bearer tokens. It is safe for concurrent use.
type Authenticator struct {
	verifier *oidc.IDTokenVerifier
	skew     time.Duration
	now      func() time.Time
}

// New builds an Authenticator that fetches and caches the issuer's JWKS via
// OIDC discovery (with rotation handling provided by go-oidc's remote key set).
// The issuer is pinned, the audience is required and checked exactly, and the
// signing algorithm is constrained to ExpectedAlg (INV-5).
//
// Expiry (exp/iat/nbf) is validated by this package with a configurable clock
// skew rather than by go-oidc, so the skew bound is honored precisely.
func New(ctx context.Context, issuer, audience string, skew time.Duration) (*Authenticator, error) {
	if audience == "" {
		return nil, errors.New("auth: audience is required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: create OIDC provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: []string{ExpectedAlg},
		SkipExpiryCheck:      true, // we validate exp/nbf/iat with skew below
	})
	return NewWithVerifier(verifier, skew), nil
}

// NewWithVerifier builds an Authenticator around a pre-constructed verifier.
// It exists so tests can supply a verifier backed by a static key set without
// contacting a real issuer.
func NewWithVerifier(verifier *oidc.IDTokenVerifier, skew time.Duration) *Authenticator {
	return &Authenticator{verifier: verifier, skew: skew, now: time.Now}
}

// Authenticate verifies a raw bearer token and returns the caller identity.
// go-oidc validates signature, issuer, audience and the algorithm allow-list;
// this method additionally enforces exp/nbf with a bounded clock skew.
func (a *Authenticator) Authenticate(ctx context.Context, rawToken string) (*Identity, error) {
	if rawToken == "" {
		return nil, errors.New("auth: empty bearer token")
	}
	idToken, err := a.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("auth: verify token: %w", err)
	}
	var c claims
	if err := idToken.Claims(&c); err != nil {
		return nil, fmt.Errorf("auth: decode claims: %w", err)
	}
	now := a.now()
	if c.Exp != 0 && now.After(time.Unix(c.Exp, 0).Add(a.skew)) {
		return nil, errors.New("auth: token expired")
	}
	if c.Nbf != 0 && now.Before(time.Unix(c.Nbf, 0).Add(-a.skew)) {
		return nil, errors.New("auth: token not yet valid")
	}
	if c.Iat != 0 && now.Before(time.Unix(c.Iat, 0).Add(-a.skew)) {
		return nil, errors.New("auth: token issued in the future")
	}
	return &Identity{
		Repository:        c.Repository,
		RepositoryID:      c.RepositoryID,
		RepositoryOwner:   c.RepositoryOwner,
		RepositoryOwnerID: c.RepositoryOwnerID,
		JobWorkflowRef:    c.JobWorkflowRef,
	}, nil
}
