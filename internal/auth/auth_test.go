package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"

	"github.com/abinnovision/gh-token-broker/internal/auth"
)

const (
	testIssuer   = "https://token.actions.githubusercontent.com"
	testAudience = "gh-token-broker"
)

type authFixture struct {
	authn *auth.Authenticator
	key   *rsa.PrivateKey
}

func newFixture(t *testing.T) authFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keySet := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	verifier := oidc.NewVerifier(testIssuer, keySet, &oidc.Config{
		ClientID:             testAudience,
		SupportedSigningAlgs: []string{auth.ExpectedAlg},
		SkipExpiryCheck:      true, // Authenticator enforces exp/nbf with skew
	})
	return authFixture{
		authn: auth.NewWithVerifier(verifier, 60*time.Second),
		key:   key,
	}
}

// signRS256 signs claims with the fixture's RSA key.
func (f authFixture) signRS256(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// validClaims returns a well-formed GitHub Actions OIDC claim set.
func validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":                 testIssuer,
		"aud":                 testAudience,
		"exp":                 now.Add(time.Hour).Unix(),
		"iat":                 now.Unix(),
		"nbf":                 now.Add(-time.Minute).Unix(),
		"repository":          "acme/app",
		"repository_id":       "123",
		"repository_owner":    "acme",
		"repository_owner_id": "456",
		"job_workflow_ref":    "acme/app/.github/workflows/ci.yml@refs/heads/main",
	}
}

func TestValidTokenHappyPath(t *testing.T) {
	f := newFixture(t)
	id, err := f.authn.Authenticate(context.Background(), f.signRS256(t, validClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if id.Repository != "acme/app" || id.RepositoryOwner != "acme" ||
		id.JobWorkflowRef != "acme/app/.github/workflows/ci.yml@refs/heads/main" {
		t.Fatalf("id-anchored claims not extracted: %+v", id)
	}
}

func TestRejectWrongIssuer(t *testing.T) {
	f := newFixture(t)
	c := validClaims()
	c["iss"] = "https://evil.example.com"
	if _, err := f.authn.Authenticate(context.Background(), f.signRS256(t, c)); err == nil {
		t.Fatal("wrong issuer must be rejected")
	}
}

func TestRejectWrongAudience(t *testing.T) {
	f := newFixture(t)
	c := validClaims()
	c["aud"] = "some-other-audience"
	if _, err := f.authn.Authenticate(context.Background(), f.signRS256(t, c)); err == nil {
		t.Fatal("wrong audience must be rejected")
	}
}

func TestRejectMissingAudience(t *testing.T) {
	f := newFixture(t)
	c := validClaims()
	delete(c, "aud")
	if _, err := f.authn.Authenticate(context.Background(), f.signRS256(t, c)); err == nil {
		t.Fatal("missing audience must be rejected")
	}
}

func TestRejectAlgNone(t *testing.T) {
	f := newFixture(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims())
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.authn.Authenticate(context.Background(), raw); err == nil {
		t.Fatal("alg=none must be rejected")
	}
}

func TestRejectExpiredBeyondSkew(t *testing.T) {
	f := newFixture(t)
	c := validClaims()
	c["exp"] = time.Now().Add(-2 * time.Minute).Unix() // beyond 60s skew
	if _, err := f.authn.Authenticate(context.Background(), f.signRS256(t, c)); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestAcceptExpiredWithinSkew(t *testing.T) {
	f := newFixture(t)
	c := validClaims()
	c["exp"] = time.Now().Add(-30 * time.Second).Unix() // within 60s skew
	if _, err := f.authn.Authenticate(context.Background(), f.signRS256(t, c)); err != nil {
		t.Fatalf("token expired within skew should be accepted: %v", err)
	}
}

func TestRejectNotYetValid(t *testing.T) {
	f := newFixture(t)
	c := validClaims()
	c["nbf"] = time.Now().Add(2 * time.Minute).Unix() // beyond 60s skew
	if _, err := f.authn.Authenticate(context.Background(), f.signRS256(t, c)); err == nil {
		t.Fatal("not-yet-valid token must be rejected")
	}
}

func TestRejectEmptyToken(t *testing.T) {
	f := newFixture(t)
	if _, err := f.authn.Authenticate(context.Background(), ""); err == nil {
		t.Fatal("empty token must be rejected")
	}
}

func TestRejectTamperedSignature(t *testing.T) {
	f := newFixture(t)
	raw := f.signRS256(t, validClaims())
	// Flip a character in the signature segment.
	tampered := raw[:len(raw)-2] + strings.Repeat("A", 2)
	if _, err := f.authn.Authenticate(context.Background(), tampered); err == nil {
		t.Fatal("tampered signature must be rejected")
	}
}
