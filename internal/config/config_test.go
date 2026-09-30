package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/abinnovision/gh-token-broker/internal/config"
)

func write(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const githubIssuer = `    - name: github
      preset: github
      audience: gh-token-broker
`

const gitlabIssuer = `    - name: gitlab
      issuer: https://gitlab.example.com
      audience: gh-token-broker
      claims: [sub, project_path]
      require:
        namespace_id: ["4711"]
`

const validConfig = `
oidc:
  issuers:
` + githubIssuer + `githubApp:
  appId: 12345
  privateKeyPath: /etc/gh-token-broker/app.pem
server:
  issuer: "https://broker.example.com"
policies:
  - name: allow-acme
    issuer: github
    condition: caller.repository_owner == "acme"
    grant:
      permissions:
        contents: read
`

// withIssuers returns validConfig with the oidc.issuers items replaced.
func withIssuers(items string) string {
	return strings.Replace(validConfig, githubIssuer, items, 1)
}

func TestLoadValidConfigAppliesDefaults(t *testing.T) {
	cfg, err := config.Load(write(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Bind != ":8080" {
		t.Errorf("default bind = %q", cfg.Server.Bind)
	}
	if cfg.OIDC.ClockSkewSeconds != 60 {
		t.Errorf("default skew = %d", cfg.OIDC.ClockSkewSeconds)
	}
	if cfg.Policy.CostLimit != 10000 || cfg.Policy.MaxRepositories != 256 {
		t.Errorf("policy defaults wrong: %+v", cfg.Policy)
	}
	if len(cfg.Policies) != 1 || cfg.Policies[0].Name != "allow-acme" || cfg.Policies[0].Issuer != "github" {
		t.Errorf("policies = %+v, want allow-acme for issuer github", cfg.Policies)
	}
}

// githubClaims is the fixed claim list of the GitHub preset.
var githubClaims = []string{
	"repository", "repository_id", "repository_owner", "repository_owner_id", "job_workflow_ref",
	"workflow_ref", "workflow_sha", "job_workflow_sha", "sha", "ref", "ref_type", "ref_protected",
	"environment", "environment_node_id", "repository_visibility", "runner_environment",
	"enterprise", "enterprise_id", "issuer_scope", "event_name", "sub",
}

func TestGitHubClaimSets(t *testing.T) {
	if !reflect.DeepEqual(config.GitHubClaims(), githubClaims) {
		t.Errorf("GitHubClaims() = %v, want %v", config.GitHubClaims(), githubClaims)
	}
	wantIdentity := []string{
		"repository", "repository_id", "repository_owner", "repository_owner_id",
		"workflow_ref", "enterprise", "enterprise_id",
	}
	if !reflect.DeepEqual(config.GitHubIdentityClaims(), wantIdentity) {
		t.Errorf("GitHubIdentityClaims() = %v, want %v", config.GitHubIdentityClaims(), wantIdentity)
	}
	for _, c := range append(config.GitHubAuditClaims(), "actor", "actor_id", "head_ref", "base_ref", "workflow") {
		if slices.Contains(config.GitHubClaims(), c) {
			t.Errorf("claim %q must not be exposed to policies", c)
		}
	}
}

func TestPresetResolution(t *testing.T) {
	tests := []struct {
		name    string
		items   string
		wantURL string
	}{
		{name: "default issuer", items: githubIssuer, wantURL: config.GitHubIssuerURL},
		{
			name:    "enterprise issuer",
			items:   githubIssuer + "      issuer: https://token.actions.githubusercontent.com/acme-corp\n",
			wantURL: config.GitHubIssuerURL + "/acme-corp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.LoadFromBytes([]byte(withIssuers(tt.items)))
			if err != nil {
				t.Fatal(err)
			}
			iss := cfg.OIDC.Issuers[0]
			if !iss.IsPreset() {
				t.Error("IsPreset() = false, want true")
			}
			if iss.Issuer != tt.wantURL {
				t.Errorf("issuer = %q, want %q", iss.Issuer, tt.wantURL)
			}
			if !reflect.DeepEqual(iss.Claims, githubClaims) {
				t.Errorf("claims = %v, want %v", iss.Claims, githubClaims)
			}
			if want := []string{"run_id", "run_number", "run_attempt", "check_run_id"}; !reflect.DeepEqual(iss.AuditClaims, want) {
				t.Errorf("audit claims = %v, want %v", iss.AuditClaims, want)
			}
			if !reflect.DeepEqual(iss.Algorithms, []string{"RS256"}) {
				t.Errorf("algorithms = %v, want [RS256]", iss.Algorithms)
			}
			if iss.MaxTokenLifetimeSeconds != 3600 {
				t.Errorf("maxTokenLifetimeSeconds = %d, want 3600", iss.MaxTokenLifetimeSeconds)
			}
		})
	}
}

func TestGenericIssuer(t *testing.T) {
	custom := strings.Replace(gitlabIssuer, "      claims:", "      algorithms: [ES256, EdDSA]\n      maxTokenLifetimeSeconds: 600\n      claims:", 1)
	tests := []struct {
		name         string
		items        string
		wantAlgs     []string
		wantLifetime int
	}{
		{name: "defaults", items: githubIssuer + gitlabIssuer, wantAlgs: []string{"RS256"}, wantLifetime: 3600},
		{name: "explicit", items: githubIssuer + custom, wantAlgs: []string{"ES256", "EdDSA"}, wantLifetime: 600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.LoadFromBytes([]byte(withIssuers(tt.items)))
			if err != nil {
				t.Fatal(err)
			}
			iss := cfg.OIDC.Issuers[1]
			if iss.IsPreset() {
				t.Error("IsPreset() = true, want false")
			}
			if iss.Issuer != "https://gitlab.example.com" {
				t.Errorf("issuer = %q", iss.Issuer)
			}
			if !reflect.DeepEqual(iss.Claims, []string{"sub", "project_path"}) {
				t.Errorf("claims = %v", iss.Claims)
			}
			if !reflect.DeepEqual(iss.Require, map[string][]string{"namespace_id": {"4711"}}) {
				t.Errorf("require = %v", iss.Require)
			}
			if !reflect.DeepEqual(iss.Algorithms, tt.wantAlgs) {
				t.Errorf("algorithms = %v, want %v", iss.Algorithms, tt.wantAlgs)
			}
			if iss.MaxTokenLifetimeSeconds != tt.wantLifetime {
				t.Errorf("maxTokenLifetimeSeconds = %d, want %d", iss.MaxTokenLifetimeSeconds, tt.wantLifetime)
			}
		})
	}
}

func TestRejectInvalidIssuers(t *testing.T) {
	gitlabWith := func(old, repl string) string {
		return githubIssuer + strings.Replace(gitlabIssuer, old, repl, 1)
	}
	gitlabURL := func(u string) string {
		return gitlabWith("https://gitlab.example.com", u)
	}
	tests := []struct {
		name    string
		items   string
		wantErr string
	}{
		{name: "no issuers", items: "", wantErr: "/oidc/issuers"},
		{name: "invalid name", items: gitlabWith("name: gitlab", "name: GitLab"), wantErr: "/oidc/issuers/1/name"},
		{name: "duplicate name", items: gitlabWith("name: gitlab", "name: github"), wantErr: `duplicate oidc issuer name "github"`},
		{name: "duplicate URL", items: githubIssuer + strings.Replace(githubIssuer, "name: github", "name: github2", 1), wantErr: "duplicate oidc issuer URL"},
		{name: "missing audience", items: strings.Replace(githubIssuer, "      audience: gh-token-broker\n", "", 1), wantErr: "audience"},
		{name: "http URL", items: gitlabURL("http://gitlab.example.com"), wantErr: "canonical https://"},
		{name: "trailing slash", items: gitlabURL("https://gitlab.example.com/"), wantErr: "canonical https://"},
		{name: "uppercase host", items: gitlabURL("https://GitLab.example.com"), wantErr: "canonical https://"},
		{name: "default port", items: gitlabURL("https://gitlab.example.com:443"), wantErr: "canonical https://"},
		{name: "query", items: gitlabURL("https://gitlab.example.com?a=b"), wantErr: "canonical https://"},
		{name: "fragment", items: gitlabURL("https://gitlab.example.com#x"), wantErr: "canonical https://"},
		{name: "trailing dot GitHub host", items: gitlabURL("https://token.actions.githubusercontent.com."), wantErr: "canonical https://"},
		{name: "trailing dot generic host", items: gitlabURL("https://gitlab.example.com."), wantErr: "canonical https://"},
		{name: "userinfo", items: gitlabURL("https://user@gitlab.example.com"), wantErr: "canonical https://"},
		{name: "unknown preset", items: strings.Replace(githubIssuer, "preset: github", "preset: gitlab", 1), wantErr: "/oidc/issuers/0/preset"},
		{name: "preset with claims", items: githubIssuer + "      claims: [sub]\n", wantErr: "claims are fixed by preset"},
		{name: "preset with added claim", items: githubIssuer + "      claims: [" + strings.Join(githubClaims, ", ") + ", actor]\n", wantErr: "claims are fixed by preset"},
		{name: "audit claims", items: githubIssuer + "      auditClaims: [actor]\n", wantErr: "auditClaims"},
		{name: "preset with foreign issuer", items: githubIssuer + "      issuer: https://gitlab.example.com\n", wantErr: "<enterprise-slug>"},
		{name: "preset with nested path", items: githubIssuer + "      issuer: https://token.actions.githubusercontent.com/acme/app\n", wantErr: "<enterprise-slug>"},
		{name: "preset with invalid slug", items: githubIssuer + "      issuer: https://token.actions.githubusercontent.com/Acme\n", wantErr: "<enterprise-slug>"},
		{name: "generic without issuer", items: gitlabWith("      issuer: https://gitlab.example.com\n", ""), wantErr: "issuer is required"},
		{name: "generic with GitHub host", items: gitlabURL("https://token.actions.githubusercontent.com/acme"), wantErr: "preset: github"},
		{name: "generic without claims", items: gitlabWith("      claims: [sub, project_path]\n", ""), wantErr: "claims must list"},
		{name: "generic without require", items: gitlabWith("      require:\n        namespace_id: [\"4711\"]\n", ""), wantErr: "require must pin"},
		{name: "require without values", items: gitlabWith(`namespace_id: ["4711"]`, "namespace_id: []"), wantErr: "at least one value"},
		{name: "require with empty value", items: gitlabWith(`namespace_id: ["4711"]`, `namespace_id: [""]`), wantErr: "must not be empty"},
		{name: "require registered claim", items: gitlabWith(`namespace_id: ["4711"]`, `aud: ["x"]`), wantErr: `claim "aud" is a registered token claim`},
		{name: "claim registered", items: gitlabWith("[sub, project_path]", "[sub, iss]"), wantErr: `claim "iss" is a registered token claim`},
		{name: "claim empty", items: gitlabWith("[sub, project_path]", `[sub, ""]`), wantErr: "claim name must not be empty"},
		{name: "claim with space", items: gitlabWith("[sub, project_path]", `[sub, "project path"]`), wantErr: "printable ASCII"},
		{name: "claim not ASCII", items: gitlabWith("[sub, project_path]", `[sub, "projekt_pfäd"]`), wantErr: "printable ASCII"},
		{name: "claim duplicate", items: gitlabWith("[sub, project_path]", "[sub, sub]"), wantErr: "/oidc/issuers/1/claims"},
		{name: "symmetric algorithm", items: githubIssuer + "      algorithms: [HS256]\n", wantErr: "/oidc/issuers/0/algorithms"},
		{name: "empty algorithms", items: githubIssuer + "      algorithms: []\n", wantErr: "/oidc/issuers/0/algorithms"},
		{name: "negative lifetime", items: githubIssuer + "      maxTokenLifetimeSeconds: -1\n", wantErr: "/oidc/issuers/0/maxTokenLifetimeSeconds"},
		{name: "lifetime over maximum", items: githubIssuer + "      maxTokenLifetimeSeconds: 86401\n", wantErr: "/oidc/issuers/0/maxTokenLifetimeSeconds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.LoadFromBytes([]byte(withIssuers(tt.items)))
			if err == nil {
				t.Fatal("config must be rejected")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestRejectClockSkewOutOfRange(t *testing.T) {
	for _, skew := range []string{"-1", "301"} {
		t.Run(skew, func(t *testing.T) {
			body := strings.Replace(validConfig, "  issuers:\n", "  clockSkewSeconds: "+skew+"\n  issuers:\n", 1)
			_, err := config.LoadFromBytes([]byte(body))
			if err == nil || !strings.Contains(err.Error(), "/oidc/clockSkewSeconds") {
				t.Fatalf("error = %v, want it to mention /oidc/clockSkewSeconds", err)
			}
		})
	}
}

func TestAcceptBoundaryLimits(t *testing.T) {
	body := strings.Replace(validConfig, "  issuers:\n", "  clockSkewSeconds: 300\n  issuers:\n", 1)
	body = strings.Replace(body, githubIssuer, githubIssuer+"      maxTokenLifetimeSeconds: 86400\n", 1)
	if _, err := config.LoadFromBytes([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectPolicyWithUnknownIssuer(t *testing.T) {
	body := strings.Replace(validConfig, "    issuer: github\n", "    issuer: gitlab\n", 1)
	_, err := config.LoadFromBytes([]byte(body))
	if err == nil || !strings.Contains(err.Error(), `policy "allow-acme": issuer "gitlab" is not configured`) {
		t.Fatalf("error = %v, want unknown issuer error", err)
	}
}

func TestRejectSingleIssuerShape(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "oidc.audience",
			body:    strings.Replace(validConfig, "  issuers:\n", "  audience: gh-token-broker\n  issuers:\n", 1),
			wantErr: "move them into an oidc.issuers entry",
		},
		{
			name: "oidc.issuer and oidc.audience",
			body: strings.Replace(
				strings.Replace(validConfig, "  issuers:\n"+githubIssuer, "  issuer: https://token.actions.githubusercontent.com\n  audience: gh-token-broker\n", 1),
				"    issuer: github\n", "", 1),
			wantErr: "preset: github",
		},
		{
			name:    "policy without issuer",
			body:    strings.Replace(validConfig, "    issuer: github\n", "", 1),
			wantErr: `policy "allow-acme" (policies[0]): issuer is required`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.LoadFromBytes([]byte(tt.body))
			if err == nil {
				t.Fatal("config must be rejected")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLint(t *testing.T) {
	pinned := githubIssuer + "      require:\n        repository_owner_id: [\"123\"]\n"
	tests := []struct {
		name  string
		items string
		want  []string
	}{
		{name: "pinned preset", items: pinned, want: nil},
		{
			name:  "preset without require",
			items: githubIssuer,
			want:  []string{`oidc issuer "github" uses preset "github" without require`},
		},
		{
			name:  "unreferenced issuer",
			items: pinned + gitlabIssuer,
			want:  []string{`oidc issuer "gitlab" is not referenced by any policy`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.LoadFromBytes([]byte(withIssuers(tt.items)))
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.Lint()
			if len(got) != len(tt.want) {
				t.Fatalf("Lint() = %q, want %d warnings", got, len(tt.want))
			}
			for i, w := range tt.want {
				if !strings.HasPrefix(got[i], w) {
					t.Errorf("Lint()[%d] = %q, want prefix %q", i, got[i], w)
				}
			}
		})
	}
}

func TestExampleConfigLoads(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if warnings := cfg.Lint(); len(warnings) != 0 {
		t.Errorf("Lint() = %q, want no warnings", warnings)
	}
}

func TestRejectLegacyTokenIssuance(t *testing.T) {
	body := strings.Replace(validConfig, "server:\n", "tokenIssuance:\n", 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("tokenIssuance must be rejected (use server.issuer)")
	}
}

func TestRejectLegacyPolicyPolicies(t *testing.T) {
	body := strings.Replace(validConfig, "policies:\n  - name: allow-acme\n", "policy:\n  policies:\n  - name: allow-acme\n", 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("policy.policies must be rejected (use top-level policies)")
	}
}

func TestPortEnvOverridesDefaultBind(t *testing.T) {
	t.Setenv("PORT", "9090")
	cfg, err := config.Load(write(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Bind != ":9090" {
		t.Errorf("bind = %q, want :9090", cfg.Server.Bind)
	}
}

func TestExplicitBindWinsOverPortEnv(t *testing.T) {
	t.Setenv("PORT", "9090")
	body := strings.Replace(validConfig, "  issuer: \"https://broker.example.com\"", "  bind: \":7000\"\n  issuer: \"https://broker.example.com\"", 1)
	cfg, err := config.Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Bind != ":7000" {
		t.Errorf("bind = %q, want :7000", cfg.Server.Bind)
	}
}

func TestLoadFromBytesParsesValidConfig(t *testing.T) {
	cfg, err := config.LoadFromBytes([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.OIDC.Issuers) != 1 || cfg.OIDC.Issuers[0].Audience != "gh-token-broker" {
		t.Errorf("issuers = %+v", cfg.OIDC.Issuers)
	}
}

func TestLoadFromBytesRejectsInvalid(t *testing.T) {
	body := strings.Replace(validConfig, "      audience: gh-token-broker\n", "", 1)
	if _, err := config.LoadFromBytes([]byte(body)); err == nil {
		t.Fatal("missing audience must be rejected")
	}
}

func TestRejectUnknownPermissionKeyInGrant(t *testing.T) {
	body := strings.Replace(validConfig, "        contents: read", "        not_a_permission: read", 1)
	_, err := config.Load(write(t, body))
	if err == nil {
		t.Fatal("unknown permission key in a grant must be rejected at load")
	}
}

func TestRejectGrantWithoutPermissions(t *testing.T) {
	body := strings.Replace(validConfig, "      permissions:\n        contents: read\n", "", 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("grant without permissions must be rejected")
	}
}

func TestRejectNoPrivateKeySource(t *testing.T) {
	body := strings.Replace(validConfig, "  privateKeyPath: /etc/gh-token-broker/app.pem\n", "", 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("missing private key source must be rejected")
	}
}

func TestRejectDuplicatePolicyName(t *testing.T) {
	dup := validConfig + `  - name: allow-acme
    issuer: github
    condition: "true"
    grant:
      permissions:
        contents: read
`
	_, err := config.Load(write(t, dup))
	if err == nil || !strings.Contains(err.Error(), "duplicate policy name") {
		t.Fatalf("error = %v, want duplicate policy name", err)
	}
}

func TestServerIssuerRequired(t *testing.T) {
	body := strings.Replace(validConfig, "server:\n  issuer: \"https://broker.example.com\"\n", "", 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("missing server.issuer must be rejected")
	}
}

func TestServerIssuerRejectsNonHTTPS(t *testing.T) {
	body := strings.Replace(validConfig, "https://broker.example.com", "http://broker.example.com", 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("non-https server.issuer must be rejected")
	}
}

func TestServerIssuerAcceptsValid(t *testing.T) {
	cfg, err := config.Load(write(t, validConfig))
	if err != nil {
		t.Fatalf("valid server.issuer must be accepted: %v", err)
	}
	if cfg.Server.Issuer != "https://broker.example.com" {
		t.Errorf("issuer = %q", cfg.Server.Issuer)
	}
}

func TestRejectLegacyPolicyProperties(t *testing.T) {
	legacyOnError := strings.Replace(validConfig, "      permissions:\n", "      onError: skip\n      permissions:\n", 1)
	if _, err := config.Load(write(t, legacyOnError)); err == nil {
		t.Fatal("legacy onError must be rejected")
	}

	legacyWhen := strings.Replace(validConfig, "    condition:", "    when:", 1)
	if _, err := config.Load(write(t, legacyWhen)); err == nil {
		t.Fatal("legacy when must be rejected")
	}

	legacyRepositories := strings.Replace(validConfig, "      permissions:\n", "      repositories: [\"acme/app\"]\n      permissions:\n", 1)
	if _, err := config.Load(write(t, legacyRepositories)); err == nil {
		t.Fatal("grant.repositories must be rejected")
	}
}

func TestAggregateGrantPermissions(t *testing.T) {
	tests := []struct {
		name     string
		policies []config.Policy
		want     map[string]string
	}{
		{
			name:     "empty policies",
			policies: nil,
			want:     map[string]string{},
		},
		{
			name: "single policy",
			policies: []config.Policy{
				{
					Grant: config.Grant{
						Permissions: map[string]string{"contents": "read", "issues": "write"},
					},
				},
			},
			want: map[string]string{"contents": "read", "issues": "write"},
		},
		{
			name: "max level wins",
			policies: []config.Policy{
				{
					Grant: config.Grant{
						Permissions: map[string]string{"contents": "read"},
					},
				},
				{
					Grant: config.Grant{
						Permissions: map[string]string{"contents": "write", "issues": "read"},
					},
				},
			},
			want: map[string]string{"contents": "write", "issues": "read"},
		},
		{
			name: "non-canonical keys excluded",
			policies: []config.Policy{
				{
					Grant: config.Grant{
						Permissions: map[string]string{"bogus": "admin", "contents": "read"},
					},
				},
			},
			want: map[string]string{"contents": "read"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Policies: tt.policies}
			got := cfg.AggregateGrantPermissions()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AggregateGrantPermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}
