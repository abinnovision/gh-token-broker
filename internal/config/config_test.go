package config_test

import (
	"os"
	"path/filepath"
	"reflect"
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

const validConfig = `
oidc:
  audience: gh-token-broker
githubApp:
  appId: 12345
  privateKeyPath: /etc/gh-token-broker/app.pem
server:
  issuer: "https://broker.example.com"
policies:
  - name: allow-acme
    condition: caller.repository_owner == "acme"
    grant:
      permissions:
        contents: read
`

func TestLoadValidConfigAppliesDefaults(t *testing.T) {
	cfg, err := config.Load(write(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Bind != ":8080" {
		t.Errorf("default bind = %q", cfg.Server.Bind)
	}
	if cfg.OIDC.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("default issuer = %q", cfg.OIDC.Issuer)
	}
	if cfg.OIDC.ClockSkewSeconds != 60 {
		t.Errorf("default skew = %d", cfg.OIDC.ClockSkewSeconds)
	}
	if cfg.Policy.CostLimit != 10000 || cfg.Policy.MaxRepositories != 256 {
		t.Errorf("policy defaults wrong: %+v", cfg.Policy)
	}
	if len(cfg.Policies) != 1 || cfg.Policies[0].Name != "allow-acme" {
		t.Errorf("policies = %+v, want allow-acme", cfg.Policies)
	}
}

func TestRejectLegacyTokenIssuance(t *testing.T) {
	body := `
oidc:
  audience: gh-token-broker
githubApp:
  appId: 12345
  privateKeyPath: /etc/gh-token-broker/app.pem
tokenIssuance:
  issuer: "https://broker.example.com"
policies:
  - name: x
    condition: "true"
    grant:
      permissions:
        contents: read
`
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("tokenIssuance must be rejected (use server.issuer)")
	}
}

func TestRejectLegacyPolicyPolicies(t *testing.T) {
	body := `
oidc:
  audience: gh-token-broker
githubApp:
  appId: 12345
  privateKeyPath: /etc/gh-token-broker/app.pem
server:
  issuer: "https://broker.example.com"
policy:
  policies:
    - name: old
      condition: "true"
      grant:
        permissions:
          contents: read
`
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
	if cfg.OIDC.Audience != "gh-token-broker" {
		t.Errorf("audience = %q", cfg.OIDC.Audience)
	}
}

func TestLoadFromBytesRejectsInvalid(t *testing.T) {
	body := strings.Replace(validConfig, "  audience: gh-token-broker\n", "", 1)
	if _, err := config.LoadFromBytes([]byte(body)); err == nil {
		t.Fatal("missing oidc.audience must be rejected")
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

func TestRejectMissingAudience(t *testing.T) {
	body := strings.Replace(validConfig, "  audience: gh-token-broker\n", "", 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("missing oidc.audience must be rejected")
	}
}

func TestRejectNoPrivateKeySource(t *testing.T) {
	body := strings.Replace(validConfig, "  privateKeyPath: /etc/gh-token-broker/app.pem\n", "", 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("missing private key source must be rejected")
	}
}

func TestRejectDuplicatePolicyName(t *testing.T) {
	dup := validConfig + `- name: allow-acme
  condition: "true"
  grant:
    permissions:
      contents: read
`
	if _, err := config.Load(write(t, dup)); err == nil {
		t.Fatal("duplicate policy name must be rejected")
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
