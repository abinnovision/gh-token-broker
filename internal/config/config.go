// Package config loads and validates the proxy's YAML configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	root "github.com/abinnovision/gh-token-broker"
	"github.com/abinnovision/gh-token-broker/internal/perm"
)

// Config is the top-level proxy configuration.
type Config struct {
	Server        ServerConfig        `yaml:"server"`
	OIDC          OIDCConfig          `yaml:"oidc"`
	GitHubApp     GitHubAppConfig     `yaml:"githubApp"`
	TokenIssuance TokenIssuanceConfig `yaml:"tokenIssuance"`
	Policy        PolicyConfig        `yaml:"policy"`
}

type ServerConfig struct {
	Bind string `yaml:"bind"`
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

// TokenIssuanceConfig gates the token-issuance endpoint. When Enabled is
// false, /token is not registered on the mux at all (not merely 403).
type TokenIssuanceConfig struct {
	Enabled bool `yaml:"enabled"`
}

type PolicyConfig struct {
	// CostLimit bounds CEL runtime cost per evaluation, guarding against
	// pathological operator expressions.
	CostLimit uint64 `yaml:"costLimit"`
	// MaxRepositories caps the size of a caller-supplied request.repositories
	// list before it is bound as a CEL activation variable.
	MaxRepositories int      `yaml:"maxRepositories"`
	Policies        []Policy `yaml:"policies"`
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
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
		cfg.Server.Bind = ":8080"
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

	seen := map[string]bool{}
	for _, p := range cfg.Policy.Policies {
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

// checkPermissions rejects any permission key not in the canonical table or
// any invalid level at load time (fail-closed at startup).
func checkPermissions(where string, perms map[string]string) error {
	for k, v := range perms {
		if !perm.ValidKey(k) {
			return fmt.Errorf("%s: unknown permission key %q (not in canonical allow-list)", where, k)
		}
		if !perm.ValidLevel(v) {
			return fmt.Errorf("%s: permission %q has invalid level %q (want read|write|admin)", where, k, v)
		}
	}
	return nil
}

// Lint returns non-fatal configuration warnings.
func (c *Config) Lint() []string {
	var warnings []string
	if c.TokenIssuance.Enabled {
		warnings = append(warnings,
			"tokenIssuance.enabled=true: the token-issuance endpoint is active; ensure this is intended")
	}
	if len(c.Policy.Policies) == 0 {
		warnings = append(warnings,
			"policy.policies is empty: every request will be denied (deny-by-default)")
	}
	return warnings
}
