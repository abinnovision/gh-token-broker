// Package auth verifies OIDC bearer tokens from the configured issuers and
// extracts the claims that policy is allowed to trust. It is the only caller
// authentication method; there is no API-key path.
//
// Each token is routed by its unverified iss to exactly one configured issuer,
// whose verifier then checks signature, algorithm and issuer. All claims used
// afterwards are read from the verified payload by exact name.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/abinnovision/gh-token-broker/internal/config"
)

const (
	// maxTokenBytes bounds the raw bearer token.
	maxTokenBytes = 16 << 10
	// maxClaimBytes bounds every string claim the broker reads.
	maxClaimBytes = 1 << 10
	// maxUnixSeconds bounds NumericDate claims to exactly representable values.
	maxUnixSeconds = 1 << 53
)

// Identity is the verified caller of one request.
type Identity struct {
	Issuer    string // configured issuer name
	IssuerURL string
	Subject   string
	TokenID   string // jti, empty when the token has none
	IssuedAt  time.Time
	Expiry    time.Time
	// Claims holds the issuer's declared claims present in the token. Boolean
	// values are rendered as "true" or "false".
	Claims map[string]string
	// AuditClaims holds the issuer's audit-only claims present in the token.
	// They are recorded in the audit log and never exposed to policies.
	AuditClaims map[string]string
}

// Authenticator verifies OIDC bearer tokens. It is safe for concurrent use.
type Authenticator struct {
	issuers map[string]*issuer // keyed by issuer URL
	algs    []jose.SignatureAlgorithm
	skew    time.Duration
	now     func() time.Time
}

// issuer pairs an issuer's configuration with a verifier built from it, so
// the routing key and the verifier's expected issuer are the same value.
type issuer struct {
	cfg      config.OIDCIssuer
	verifier *oidc.IDTokenVerifier
}

// New builds an Authenticator for the resolved issuers. Each issuer is
// discovered over its own restricted HTTP client (see discover); any issuer
// failing discovery fails startup. exp, iat and nbf are validated by this
// package with the given clock skew rather than by go-oidc.
func New(ctx context.Context, issuers []config.OIDCIssuer, skew time.Duration) (*Authenticator, error) {
	return newAuthenticator(issuers, skew, func(iss config.OIDCIssuer) (oidc.KeySet, error) {
		return discover(ctx, iss.Issuer, nil)
	})
}

// newAuthenticator builds an Authenticator using keySet to obtain each
// issuer's signing keys.
func newAuthenticator(issuers []config.OIDCIssuer, skew time.Duration, keySet func(config.OIDCIssuer) (oidc.KeySet, error)) (*Authenticator, error) {
	if len(issuers) == 0 {
		return nil, errors.New("auth: at least one issuer is required")
	}
	a := &Authenticator{issuers: map[string]*issuer{}, skew: skew, now: time.Now}
	for _, cfg := range issuers {
		switch {
		case cfg.Issuer == "":
			return nil, fmt.Errorf("auth: issuer %q: issuer URL is required", cfg.Name)
		case cfg.Audience == "":
			return nil, fmt.Errorf("auth: issuer %q: audience is required", cfg.Name)
		case len(cfg.Algorithms) == 0:
			return nil, fmt.Errorf("auth: issuer %q: algorithms are required", cfg.Name)
		case cfg.MaxTokenLifetimeSeconds <= 0:
			return nil, fmt.Errorf("auth: issuer %q: maxTokenLifetimeSeconds must be positive", cfg.Name)
		}
		if _, dup := a.issuers[cfg.Issuer]; dup {
			return nil, fmt.Errorf("auth: duplicate issuer URL %q", cfg.Issuer)
		}
		ks, err := keySet(cfg)
		if err != nil {
			return nil, fmt.Errorf("auth: issuer %q: %w", cfg.Name, err)
		}
		a.issuers[cfg.Issuer] = &issuer{
			cfg: cfg,
			verifier: oidc.NewVerifier(cfg.Issuer, ks, &oidc.Config{
				ClientID:             cfg.Audience,
				SupportedSigningAlgs: cfg.Algorithms,
				SkipExpiryCheck:      true, // exp/nbf/iat are validated with skew below
			}),
		}
		for _, alg := range cfg.Algorithms {
			if !slices.Contains(a.algs, jose.SignatureAlgorithm(alg)) {
				a.algs = append(a.algs, jose.SignatureAlgorithm(alg))
			}
		}
	}
	return a, nil
}

// Authenticate verifies a raw bearer token and returns the caller identity.
// Returned errors never contain unbounded token content.
func (a *Authenticator) Authenticate(ctx context.Context, rawToken string) (*Identity, error) {
	if rawToken == "" {
		return nil, errors.New("auth: empty bearer token")
	}
	if len(rawToken) > maxTokenBytes {
		return nil, fmt.Errorf("auth: token exceeds %d bytes", maxTokenBytes)
	}

	// Route by the unverified iss. encoding/json matches go-oidc's own
	// decoding, and the selected verifier re-checks iss after verification.
	jws, err := jose.ParseSignedCompact(rawToken, a.algs)
	if err != nil {
		return nil, fmt.Errorf("auth: parse token: %.200q", err.Error())
	}
	var unverified struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &unverified); err != nil {
		return nil, fmt.Errorf("auth: decode token payload: %.200q", err.Error())
	}
	iss, ok := a.issuers[unverified.Iss]
	if !ok {
		return nil, fmt.Errorf("auth: unknown issuer %.200q", unverified.Iss)
	}

	idToken, err := iss.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("auth: issuer %q: verify token: %.200q", iss.cfg.Name, err.Error())
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("auth: issuer %q: decode claims: %.200q", iss.cfg.Name, err.Error())
	}
	id, err := a.identity(iss.cfg, claims)
	if err != nil {
		return nil, fmt.Errorf("auth: issuer %q: %w", iss.cfg.Name, err)
	}
	return id, nil
}

// identity enforces the registered-claim, claim-type and require rules on
// verified claims and builds the Identity.
func (a *Authenticator) identity(cfg config.OIDCIssuer, claims map[string]any) (*Identity, error) {
	if claims["iss"] != cfg.Issuer {
		return nil, errors.New("iss claim does not match the issuer")
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != cfg.Audience {
			return nil, errors.New("aud claim does not match the audience")
		}
	case []any:
		if len(aud) != 1 || aud[0] != cfg.Audience {
			return nil, errors.New("aud claim must be exactly the configured audience")
		}
	default:
		return nil, errors.New("aud claim missing or invalid")
	}

	exp, err := numericDate(claims, "exp")
	if err != nil {
		return nil, err
	}
	iat, err := numericDate(claims, "iat")
	if err != nil {
		return nil, err
	}
	if lifetime := exp.Sub(iat); lifetime < 0 || lifetime > time.Duration(cfg.MaxTokenLifetimeSeconds)*time.Second {
		return nil, fmt.Errorf("token lifetime exceeds %ds", cfg.MaxTokenLifetimeSeconds)
	}
	now := a.now()
	if now.After(exp.Add(a.skew)) {
		return nil, errors.New("token expired")
	}
	if now.Before(iat.Add(-a.skew)) {
		return nil, errors.New("token issued in the future")
	}
	if _, ok := claims["nbf"]; ok {
		nbf, err := numericDate(claims, "nbf")
		if err != nil {
			return nil, err
		}
		if now.Before(nbf.Add(-a.skew)) {
			return nil, errors.New("token not yet valid")
		}
	}

	sub, ok, err := stringClaim(claims, "sub")
	if err != nil {
		return nil, err
	}
	if !ok || sub == "" {
		return nil, errors.New("sub claim missing")
	}
	jti, _, err := stringClaim(claims, "jti")
	if err != nil {
		return nil, err
	}

	exposed := map[string]string{}
	for _, name := range cfg.Claims {
		v, ok, err := stringClaim(claims, name)
		if err != nil {
			return nil, err
		}
		if ok {
			exposed[name] = v
		}
	}
	for name, allowed := range cfg.Require {
		v, ok, err := stringClaim(claims, name)
		if err != nil {
			return nil, err
		}
		if !ok || !slices.Contains(allowed, v) {
			return nil, fmt.Errorf("required claim %q missing or not an allowed value", name)
		}
	}
	recorded := map[string]string{}
	for _, name := range cfg.AuditClaims {
		if v, ok := auditClaim(claims, name); ok {
			recorded[name] = v
		}
	}

	return &Identity{
		Issuer:      cfg.Name,
		IssuerURL:   cfg.Issuer,
		Subject:     sub,
		TokenID:     jti,
		IssuedAt:    iat,
		Expiry:      exp,
		Claims:      exposed,
		AuditClaims: recorded,
	}, nil
}

// numericDate returns the required NumericDate claim name.
func numericDate(claims map[string]any, name string) (time.Time, error) {
	v, ok := claims[name].(float64)
	if !ok || v < 0 || v > maxUnixSeconds {
		return time.Time{}, fmt.Errorf("%s claim missing or not a valid NumericDate", name)
	}
	return time.Unix(int64(v), 0), nil
}

// stringClaim returns claim name as a string and whether it is present. A
// present claim must be a string of at most maxClaimBytes or a boolean.
func stringClaim(claims map[string]any, name string) (string, bool, error) {
	raw, ok := claims[name]
	if !ok {
		return "", false, nil
	}
	switch v := raw.(type) {
	case string:
		if len(v) > maxClaimBytes {
			return "", false, fmt.Errorf("claim %q exceeds %d bytes", name, maxClaimBytes)
		}
		return v, true, nil
	case bool:
		if v {
			return "true", true, nil
		}
		return "false", true, nil
	default:
		return "", false, fmt.Errorf("claim %q must be a string or boolean", name)
	}
}

// auditClaim returns claim name rendered for the audit log and whether it is
// recorded. Strings are taken as is and whole JSON numbers are rendered
// without exponent. Other values and values over maxClaimBytes are skipped
// rather than rejecting the token, since the claim carries no authorization
// weight.
func auditClaim(claims map[string]any, name string) (string, bool) {
	var s string
	switch v := claims[name].(type) {
	case string:
		s = v
	case float64:
		if v != math.Trunc(v) {
			return "", false
		}
		s = strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return "", false
	}
	return s, len(s) <= maxClaimBytes
}
