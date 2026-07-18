// Package config loads and validates the proxy's YAML configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	root "github.com/abinnovision/gh-token-broker"
	"github.com/abinnovision/gh-token-broker/internal/perm"
)

// Config is the top-level proxy configuration.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	OIDC      OIDCConfig      `yaml:"oidc"`
	GitHubApp GitHubAppConfig `yaml:"githubApp"`
	Policy    PolicyConfig    `yaml:"policy"`
	Policies  []Policy        `yaml:"policies"`
}

type ServerConfig struct {
	Bind   string `yaml:"bind"`
	Issuer string `yaml:"issuer"`
}

type OIDCConfig struct {
	Issuer           string `yaml:"issuer"`
	Audience         string `yaml:"audience"`
	ClockSkewSeconds int    `yaml:"clockSkewSeconds"`
}

// GitHubAppConfig references the App private key by file path or environment
// variable name — never by raw PEM content in YAML, so key material never
// lands in the config file or logs.
type GitHubAppConfig struct {
	AppID          int64  `yaml:"appId"`
	PrivateKeyPath string `yaml:"privateKeyPath"`
	PrivateKeyEnv  string `yaml:"privateKeyEnv"`
}

type PolicyConfig struct {
	CostLimit       uint64 `yaml:"costLimit"`
	MaxRepositories int    `yaml:"maxRepositories"`
}

// Policy is one independent allow policy. Only Condition is a CEL expression;
// Grant is static operator-authored config data. CEL only decides whether the
// operator's pre-declared grant contributes to an authorization — it can
// never fabricate a novel grant from request data.
type Policy struct {
	Name      string `yaml:"name"`
	Condition string `yaml:"condition"`
	Grant     Grant  `yaml:"grant"`
}

type Grant struct {
	Permissions map[string]string `yaml:"permissions"`
}

// Load reads, schema-validates, and decodes the YAML config at path, applies
// defaults, then enforces semantic invariants (canonical permission keys,
// key material sourcing).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator-supplied config file path from the -config flag
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes runs the same schema-validate/decode/defaults/validate
// pipeline as Load, but against an in-memory YAML document. This lets
// serverless deployments supply the whole config via an environment variable
// instead of a mounted file.
func LoadFromBytes(data []byte) (*Config, error) {
	if err := validateSchema(data); err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validateSchema round-trips the YAML through JSON so the validator sees plain
// JSON value types, then validates against the embedded schema.
func validateSchema(data []byte) error {
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("config is not JSON-representable: %w", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("parse config document: %w", err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(root.ConfigSchema))
	if err != nil {
		return fmt.Errorf("parse embedded schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("config.schema.json", schemaDoc); err != nil {
		return fmt.Errorf("register schema: %w", err)
	}
	schema, err := compiler.Compile("config.schema.json")
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	if err := schema.Validate(doc); err != nil {
		return fmt.Errorf("config schema validation: %w", err)
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.Server.Bind == "" {
		if port := os.Getenv("PORT"); port != "" {
			cfg.Server.Bind = ":" + port
		} else {
			cfg.Server.Bind = ":8080"
		}
	}
	if cfg.OIDC.Issuer == "" {
		cfg.OIDC.Issuer = "https://token.actions.githubusercontent.com"
	}
	if cfg.OIDC.ClockSkewSeconds == 0 {
		cfg.OIDC.ClockSkewSeconds = 60
	}
	if cfg.Policy.CostLimit == 0 {
		cfg.Policy.CostLimit = 10000
	}
	if cfg.Policy.MaxRepositories == 0 {
		cfg.Policy.MaxRepositories = 256
	}
}

// validate enforces semantic invariants beyond the structural schema.
func validate(cfg *Config) error {
	if cfg.OIDC.Audience == "" {
		return fmt.Errorf("oidc.audience is required (a proxy-specific audience must be enforced)")
	}
	if cfg.GitHubApp.AppID == 0 {
		return fmt.Errorf("githubApp.appId is required")
	}
	if cfg.GitHubApp.PrivateKeyPath == "" && cfg.GitHubApp.PrivateKeyEnv == "" {
		return fmt.Errorf("githubApp: one of privateKeyPath or privateKeyEnv is required")
	}
	if cfg.GitHubApp.PrivateKeyPath != "" && cfg.GitHubApp.PrivateKeyEnv != "" {
		return fmt.Errorf("githubApp: set only one of privateKeyPath or privateKeyEnv")
	}
	if cfg.Server.Issuer == "" {
		return fmt.Errorf("server.issuer is required")
	}
	u, err := url.Parse(cfg.Server.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("server.issuer must be an absolute https:// URL")
	}

	seen := map[string]bool{}
	for _, p := range cfg.Policies {
		if seen[p.Name] {
			return fmt.Errorf("duplicate policy name %q", p.Name)
		}
		seen[p.Name] = true
		if err := checkPermissions(fmt.Sprintf("policy %q grant", p.Name), p.Grant.Permissions); err != nil {
			return err
		}
	}
	return nil
}

// checkPermissions rejects any permission key not in the canonical table, any
// invalid level, or any key/level combination that GitHub does not support.
func checkPermissions(where string, perms map[string]string) error {
	for k, v := range perms {
		if !perm.ValidKey(k) {
			return fmt.Errorf("%s: unknown permission key %q (not in canonical allow-list)", where, k)
		}
		if !perm.ValidKeyLevel(k, v) {
			return fmt.Errorf("%s: permission %q does not support level %q", where, k, v)
		}
	}
	return nil
}

// AggregateGrantPermissions merges the grant permissions across all policies,
// keeping the highest level (read < write < admin) for each canonical key.
// Non-canonical keys or invalid levels are dropped (fail-closed).
func (c *Config) AggregateGrantPermissions() map[string]string {
	agg := map[string]string{}
	for _, p := range c.Policies {
		for k, v := range p.Grant.Permissions {
			if !perm.ValidKey(k) || !perm.ValidLevel(v) {
				continue
			}
			existing, ok := agg[k]
			if !ok || perm.LevelOrd(v) > perm.LevelOrd(existing) {
				agg[k] = v
			}
		}
	}
	return agg
}

// Lint returns non-fatal configuration warnings.
func (c *Config) Lint() []string {
	var warnings []string
	if len(c.Policies) == 0 {
		warnings = append(warnings,
			"policies is empty: every request will be denied (deny-by-default)")
	}
	return warnings
}
