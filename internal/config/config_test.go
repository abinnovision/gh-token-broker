package config_test

import (
	"os"
	"path/filepath"
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
policy:
  rules:
    - name: allow-acme
      when: caller.repository_owner == "acme"
      grant:
        repositories: ["acme/app"]
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
	if cfg.Policy.Rules[0].OnError != "reject" {
		t.Errorf("onError default should be reject (fail closed), got %q", cfg.Policy.Rules[0].OnError)
	}
	if cfg.TokenIssuance.Enabled {
		t.Error("tokenIssuance.enabled must default to false")
	}
}

func TestRejectUnknownPermissionKeyInGrant(t *testing.T) {
	body := strings.Replace(validConfig, "          contents: read", "          not_a_permission: read", 1)
	_, err := config.Load(write(t, body))
	if err == nil {
		t.Fatal("unknown permission key in a grant must be rejected at load")
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

func TestRejectDuplicateRuleName(t *testing.T) {
	dup := validConfig + `
    - name: allow-acme
      when: "true"
      grant:
        permissions:
          contents: read
`
	if _, err := config.Load(write(t, dup)); err == nil {
		t.Fatal("duplicate rule name must be rejected")
	}
}
