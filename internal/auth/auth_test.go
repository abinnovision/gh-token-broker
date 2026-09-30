package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"

	"github.com/abinnovision/gh-token-broker/internal/auth"
	"github.com/abinnovision/gh-token-broker/internal/config"
)

const (
	githubURL     = config.GitHubIssuerURL
	enterpriseURL = config.GitHubIssuerURL + "/acme"
	gitlabURL     = "https://gitlab.example.com"
	testAudience  = "gh-token-broker"
)

var (
	githubKey = mustKey()
	gitlabKey = mustKey()

	// keys maps issuer names to the key their static key set trusts. The
	// enterprise issuer shares GitHub's key set, as on github.com.
	keys = map[string]*rsa.PrivateKey{"github": githubKey, "enterprise": githubKey, "gitlab": gitlabKey}
)

func mustKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func githubIssuer() config.OIDCIssuer {
	return config.OIDCIssuer{
		Name:                    "github",
		Preset:                  config.GitHubPreset,
		Issuer:                  githubURL,
		Audience:                testAudience,
		Algorithms:              []string{"RS256"},
		MaxTokenLifetimeSeconds: 3600,
		Claims:                  config.GitHubClaims(),
		AuditClaims:             config.GitHubAuditClaims(),
	}
}

func enterpriseIssuer() config.OIDCIssuer {
	iss := githubIssuer()
	iss.Name = "enterprise"
	iss.Issuer = enterpriseURL
	return iss
}

func gitlabIssuer() config.OIDCIssuer {
	return config.OIDCIssuer{
		Name:                    "gitlab",
		Issuer:                  gitlabURL,
		Audience:                testAudience,
		Algorithms:              []string{"RS256", "RS384"},
		MaxTokenLifetimeSeconds: 3600,
		Claims:                  []string{"sub", "project_path", "ref_protected"},
		Require:                 map[string][]string{"namespace_id": {"4711", "4712"}},
	}
}

// newAuth builds an Authenticator for the given issuers (GitHub and GitLab by
// default) backed by static key sets.
func newAuth(t *testing.T, issuers ...config.OIDCIssuer) *auth.Authenticator {
	t.Helper()
	if len(issuers) == 0 {
		issuers = []config.OIDCIssuer{githubIssuer(), gitlabIssuer()}
	}
	keySets := map[string]oidc.KeySet{}
	for _, iss := range issuers {
		keySets[iss.Name] = &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&keys[iss.Name].PublicKey}}
	}
	a, err := auth.NewWithKeySets(issuers, keySets, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func githubClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":                 githubURL,
		"aud":                 testAudience,
		"sub":                 "repo:acme/app:ref:refs/heads/main",
		"jti":                 "jti-1",
		"exp":                 now.Add(10 * time.Minute).Unix(),
		"iat":                 now.Unix(),
		"nbf":                 now.Add(-time.Minute).Unix(),
		"repository":          "acme/app",
		"repository_id":       "123",
		"repository_owner":    "acme",
		"repository_owner_id": "456",
		"job_workflow_ref":    "acme/app/.github/workflows/ci.yml@refs/heads/main",
		"ref":                 "refs/heads/main",
	}
}

func gitlabClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":           gitlabURL,
		"aud":           testAudience,
		"sub":           "project_path:acme/app:ref_type:branch:ref:main",
		"exp":           now.Add(10 * time.Minute).Unix(),
		"iat":           now.Unix(),
		"project_path":  "acme/app",
		"ref_protected": true,
		"namespace_id":  "4711",
		"user_email":    "dev@example.com",
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signRaw signs payload as a compact JWS with the given method and key.
func signRaw(t *testing.T, method jwt.SigningMethod, key any, payload []byte) string {
	t.Helper()
	signing := b64(fmt.Appendf(nil, `{"alg":%q,"typ":"JWT"}`, method.Alg())) + "." + b64(payload)
	sig, err := method.Sign(signing, key)
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(t, jwt.SigningMethodRS256, key, payload)
}

func mustAuthenticate(t *testing.T, a *auth.Authenticator, token string) *auth.Identity {
	t.Helper()
	id, err := a.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("token rejected: %v", err)
	}
	return id
}

func mustReject(t *testing.T, a *auth.Authenticator, token string) {
	t.Helper()
	_, err := a.Authenticate(context.Background(), token)
	if err == nil {
		t.Fatal("token accepted, want rejection")
	}
	t.Logf("rejected: %v", err)
}

func TestRoutesToGitHubIssuer(t *testing.T) {
	c := githubClaims()
	id := mustAuthenticate(t, newAuth(t), sign(t, githubKey, c))
	if id.Issuer != "github" || id.IssuerURL != githubURL {
		t.Fatalf("issuer = %q %q", id.Issuer, id.IssuerURL)
	}
	if id.Subject != c["sub"] || id.TokenID != "jti-1" {
		t.Fatalf("subject/token id = %q %q", id.Subject, id.TokenID)
	}
	if id.Expiry.Unix() != c["exp"] || id.IssuedAt.Unix() != c["iat"] {
		t.Fatalf("times = %v %v", id.IssuedAt, id.Expiry)
	}
	want := map[string]string{
		"sub":                 "repo:acme/app:ref:refs/heads/main",
		"repository":          "acme/app",
		"repository_id":       "123",
		"repository_owner":    "acme",
		"repository_owner_id": "456",
		"job_workflow_ref":    "acme/app/.github/workflows/ci.yml@refs/heads/main",
		"ref":                 "refs/heads/main",
	}
	if fmt.Sprint(id.Claims) != fmt.Sprint(want) {
		t.Fatalf("claims = %v, want %v", id.Claims, want)
	}
}

// fullGitHubClaims returns githubClaims with every claim GitHub Actions can
// put into a token.
func fullGitHubClaims() map[string]any {
	c := githubClaims()
	for k, v := range map[string]any{
		"workflow_ref":          "acme/app/.github/workflows/ci.yml@refs/heads/main",
		"workflow_sha":          "abc",
		"job_workflow_sha":      "abc",
		"sha":                   "abc",
		"ref_type":              "branch",
		"ref_protected":         "true",
		"environment":           "prod",
		"environment_node_id":   "EN_1",
		"repository_visibility": "private",
		"runner_environment":    "github-hosted",
		"enterprise":            "acme-corp",
		"enterprise_id":         "7",
		"issuer_scope":          "enterprise",
		"event_name":            "push",
		"actor":                 "octocat",
		"actor_id":              "1",
		"head_ref":              "feature",
		"base_ref":              "main",
		"workflow":              "CI",
		"run_id":                "100",
		"run_number":            "5",
		"run_attempt":           "1",
		"check_run_id":          "200",
	} {
		c[k] = v
	}
	return c
}

func TestGitHubPresetClaims(t *testing.T) {
	c := fullGitHubClaims()
	id := mustAuthenticate(t, newAuth(t), sign(t, githubKey, c))
	for _, name := range config.GitHubClaims() {
		if id.Claims[name] != c[name] {
			t.Errorf("claim %s = %q, want %q", name, id.Claims[name], c[name])
		}
	}
	for _, name := range []string{"actor", "actor_id", "head_ref", "base_ref", "workflow", "run_id", "run_number", "run_attempt", "check_run_id"} {
		if v, ok := id.Claims[name]; ok {
			t.Errorf("claim %s exposed to policies: %q", name, v)
		}
	}
	if len(id.Claims) != len(config.GitHubClaims()) {
		t.Errorf("claims = %v, want exactly the preset claims", id.Claims)
	}
}

func TestRefProtectedBooleanOrString(t *testing.T) {
	for _, v := range []any{true, "true"} {
		c := githubClaims()
		c["ref_protected"] = v
		id := mustAuthenticate(t, newAuth(t), sign(t, githubKey, c))
		if id.Claims["ref_protected"] != "true" {
			t.Errorf("ref_protected %#v = %q, want \"true\"", v, id.Claims["ref_protected"])
		}
	}
}

func TestAuditClaims(t *testing.T) {
	want := map[string]string{"run_id": "100", "run_number": "5", "run_attempt": "1", "check_run_id": "200"}
	for name, runNumber := range map[string]any{"string": "5", "number": 5} {
		t.Run(name, func(t *testing.T) {
			c := fullGitHubClaims()
			c["run_number"] = runNumber
			id := mustAuthenticate(t, newAuth(t), sign(t, githubKey, c))
			if fmt.Sprint(id.AuditClaims) != fmt.Sprint(want) {
				t.Errorf("audit claims = %v, want %v", id.AuditClaims, want)
			}
		})
	}
}

func TestInvalidAuditClaimIsSkipped(t *testing.T) {
	cases := map[string]any{
		"object":   map[string]any{"a": "b"},
		"array":    []string{"5"},
		"null":     nil,
		"boolean":  true,
		"fraction": 5.5,
		"too long": strings.Repeat("5", 1025),
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			c := fullGitHubClaims()
			c["run_number"] = v
			id := mustAuthenticate(t, newAuth(t), sign(t, githubKey, c))
			if got, ok := id.AuditClaims["run_number"]; ok {
				t.Errorf("run_number recorded as %q", got)
			}
			if id.AuditClaims["run_id"] != "100" {
				t.Errorf("audit claims = %v, want the valid claims kept", id.AuditClaims)
			}
		})
	}
}

func TestLargeWholeNumberAuditClaim(t *testing.T) {
	c := githubClaims()
	c["run_id"] = 12345678901234
	id := mustAuthenticate(t, newAuth(t), sign(t, githubKey, c))
	if id.AuditClaims["run_id"] != "12345678901234" {
		t.Errorf("run_id = %q, want 12345678901234", id.AuditClaims["run_id"])
	}
}

func TestRoutesToGitLabIssuer(t *testing.T) {
	id := mustAuthenticate(t, newAuth(t), sign(t, gitlabKey, gitlabClaims()))
	if id.Issuer != "gitlab" || id.IssuerURL != gitlabURL || id.TokenID != "" {
		t.Fatalf("identity = %+v", id)
	}
	// Boolean claims are exposed as strings; require-only and undeclared
	// claims are not exposed.
	want := map[string]string{
		"sub":           "project_path:acme/app:ref_type:branch:ref:main",
		"project_path":  "acme/app",
		"ref_protected": "true",
	}
	if fmt.Sprint(id.Claims) != fmt.Sprint(want) {
		t.Fatalf("claims = %v, want %v", id.Claims, want)
	}
}

func TestDeclaredClaimMayBeAbsent(t *testing.T) {
	c := gitlabClaims()
	delete(c, "ref_protected")
	id := mustAuthenticate(t, newAuth(t), sign(t, gitlabKey, c))
	if _, ok := id.Claims["ref_protected"]; ok {
		t.Fatalf("absent claim exposed: %v", id.Claims)
	}
}

func TestRejectUnknownIssuer(t *testing.T) {
	a := newAuth(t)
	c := githubClaims()
	c["iss"] = "https://evil.example.com/" + strings.Repeat("a", 5000)
	_, err := a.Authenticate(context.Background(), sign(t, githubKey, c))
	if err == nil {
		t.Fatal("unknown issuer must be rejected")
	}
	if len(err.Error()) > 300 {
		t.Fatalf("error includes unbounded issuer (%d bytes)", len(err.Error()))
	}
}

func TestRejectTokenSignedByOtherIssuer(t *testing.T) {
	mustReject(t, newAuth(t), sign(t, gitlabKey, githubClaims()))
}

// signWithTail signs the claims without the named keys, followed by tail as
// the last members of the JSON object, so member order is controlled.
func signWithTail(t *testing.T, key *rsa.PrivateKey, claims map[string]any, drop, tail string) string {
	t.Helper()
	delete(claims, drop)
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload[:len(payload)-1], tail+"}"...)
	return signRaw(t, jwt.SigningMethodRS256, key, payload)
}

// mustRejectWith requires a rejection whose error contains want.
func mustRejectWith(t *testing.T, a *auth.Authenticator, token, want string) {
	t.Helper()
	_, err := a.Authenticate(context.Background(), token)
	if err == nil {
		t.Fatal("token accepted, want rejection")
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
}

// encoding/json matches "ISS" to the iss field and the last member wins, so
// routing and go-oidc see GitLab's URL while the exact "iss" member names
// GitHub. Only the exact-key check rejects this token.
func TestRejectCaseVariantIssuerKey(t *testing.T) {
	tail := fmt.Sprintf(`,"iss":%q,"ISS":%q`, githubURL, gitlabURL)
	token := signWithTail(t, gitlabKey, gitlabClaims(), "iss", tail)
	mustRejectWith(t, newAuth(t), token, "iss claim does not match the issuer")
}

// go-oidc's audience check sees the case-variant AUD member, which is the
// configured audience, while the exact "aud" member names another audience.
func TestRejectCaseVariantAudienceKey(t *testing.T) {
	tail := fmt.Sprintf(`,"aud":"other","AUD":%q`, testAudience)
	token := signWithTail(t, githubKey, githubClaims(), "aud", tail)
	mustRejectWith(t, newAuth(t), token, "aud claim does not match the audience")
}

func TestEnterpriseIssuerDoesNotAcceptDefaultIssuer(t *testing.T) {
	c := githubClaims()
	mustReject(t, newAuth(t, enterpriseIssuer()), sign(t, githubKey, c))

	id := mustAuthenticate(t, newAuth(t, githubIssuer(), enterpriseIssuer()), sign(t, githubKey, c))
	if id.Issuer != "github" {
		t.Fatalf("default issuer token authenticated as %q", id.Issuer)
	}

	c["iss"] = enterpriseURL
	id = mustAuthenticate(t, newAuth(t, githubIssuer(), enterpriseIssuer()), sign(t, githubKey, c))
	if id.Issuer != "enterprise" {
		t.Fatalf("enterprise token authenticated as %q", id.Issuer)
	}
}

func TestAlgorithmAllowListIsPerIssuer(t *testing.T) {
	a := newAuth(t)
	sign384 := func(key *rsa.PrivateKey, c map[string]any) string {
		payload, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return signRaw(t, jwt.SigningMethodRS384, key, payload)
	}
	// RS384 is allowed for GitLab only.
	mustAuthenticate(t, a, sign384(gitlabKey, gitlabClaims()))
	mustReject(t, a, sign384(githubKey, githubClaims()))
}

func TestRejectAlgNone(t *testing.T) {
	payload, err := json.Marshal(githubClaims())
	if err != nil {
		t.Fatal(err)
	}
	mustReject(t, newAuth(t), signRaw(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, payload))
}

func TestRejectInvalidRegisteredClaims(t *testing.T) {
	now := time.Now()
	cases := map[string]func(c map[string]any){
		"missing exp": func(c map[string]any) { delete(c, "exp") },
		"missing iat": func(c map[string]any) { delete(c, "iat") },
		"string exp":  func(c map[string]any) { c["exp"] = fmt.Sprint(now.Add(time.Minute).Unix()) },
		"lifetime over cap": func(c map[string]any) {
			c["iat"] = now.Add(-time.Minute).Unix()
			c["exp"] = now.Add(3540*time.Second + time.Second).Unix()
		},
		"exp before iat": func(c map[string]any) { c["iat"] = now.Unix(); c["exp"] = now.Add(-10 * time.Second).Unix() },
		"expired beyond skew": func(c map[string]any) {
			c["exp"] = now.Add(-2 * time.Minute).Unix()
			c["iat"] = now.Add(-5 * time.Minute).Unix()
		},
		"nbf beyond skew":  func(c map[string]any) { c["nbf"] = now.Add(2 * time.Minute).Unix() },
		"iat beyond skew":  func(c map[string]any) { c["iat"] = now.Add(2 * time.Minute).Unix() },
		"two audiences":    func(c map[string]any) { c["aud"] = []string{testAudience, "other"} },
		"wrong audience":   func(c map[string]any) { c["aud"] = "other" },
		"missing audience": func(c map[string]any) { delete(c, "aud") },
		"missing sub":      func(c map[string]any) { delete(c, "sub") },
		"non-string jti":   func(c map[string]any) { c["jti"] = 7 },
	}
	a := newAuth(t)
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := githubClaims()
			mutate(c)
			mustReject(t, a, sign(t, githubKey, c))
		})
	}
}

func TestAcceptBoundaryRegisteredClaims(t *testing.T) {
	now := time.Now()
	cases := map[string]func(c map[string]any){
		"lifetime at cap": func(c map[string]any) {
			c["iat"] = now.Add(-time.Minute).Unix()
			c["exp"] = now.Add(3540 * time.Second).Unix()
		},
		"expired within skew": func(c map[string]any) {
			c["exp"] = now.Add(-30 * time.Second).Unix()
			c["iat"] = now.Add(-time.Minute).Unix()
		},
		"single-item aud array": func(c map[string]any) { c["aud"] = []string{testAudience} },
		"no nbf":                func(c map[string]any) { delete(c, "nbf") },
	}
	a := newAuth(t)
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := githubClaims()
			mutate(c)
			mustAuthenticate(t, a, sign(t, githubKey, c))
		})
	}
}

func TestRejectOversizedToken(t *testing.T) {
	c := githubClaims()
	c["padding"] = strings.Repeat("a", 16<<10)
	mustReject(t, newAuth(t), sign(t, githubKey, c))
}

func TestRejectInvalidDeclaredClaim(t *testing.T) {
	cases := map[string]any{
		"number":    123,
		"object":    map[string]any{"a": "b"},
		"array":     []string{"acme/app"},
		"null":      nil,
		"too long":  strings.Repeat("a", 1025),
		"float":     1.5,
		"bool list": []bool{true},
	}
	a := newAuth(t)
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			c := githubClaims()
			c["repository_id"] = v
			mustReject(t, a, sign(t, githubKey, c))
		})
	}
}

func TestClaimNamesAreExact(t *testing.T) {
	c := githubClaims()
	delete(c, "repository")
	c["Repository"] = "acme/app"
	id := mustAuthenticate(t, newAuth(t), sign(t, githubKey, c))
	if _, ok := id.Claims["repository"]; ok {
		t.Fatalf("case-variant claim exposed: %v", id.Claims)
	}
}

func TestRequire(t *testing.T) {
	cases := map[string]struct {
		mutate func(c map[string]any)
		ok     bool
	}{
		"second allowed value": {func(c map[string]any) { c["namespace_id"] = "4712" }, true},
		"mismatch":             {func(c map[string]any) { c["namespace_id"] = "999" }, false},
		"missing":              {func(c map[string]any) { delete(c, "namespace_id") }, false},
		"case-variant name":    {func(c map[string]any) { delete(c, "namespace_id"); c["Namespace_Id"] = "4711" }, false},
		"number":               {func(c map[string]any) { c["namespace_id"] = 4711 }, false},
		"too long":             {func(c map[string]any) { c["namespace_id"] = strings.Repeat("4", 1025) }, false},
	}
	a := newAuth(t)
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := gitlabClaims()
			tc.mutate(c)
			_, err := a.Authenticate(context.Background(), sign(t, gitlabKey, c))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestRejectEmptyToken(t *testing.T) {
	mustReject(t, newAuth(t), "")
}

func TestRejectTamperedSignature(t *testing.T) {
	raw := sign(t, githubKey, githubClaims())
	mustReject(t, newAuth(t), raw[:len(raw)-2]+"AA")
}

func TestRejectJSONSerialization(t *testing.T) {
	mustReject(t, newAuth(t), `{"payload":"e30","protected":"e30","signature":""}`)
}
