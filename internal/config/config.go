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
	Server        ServerConfig            `yaml:"server"`
	OIDC          OIDCConfig              `yaml:"oidc"`
	GitHubApp     GitHubAppConfig         `yaml:"githubApp"`
	TokenIssuance TokenIssuanceConfig     `yaml:"tokenIssuance"`
	Policy        PolicyConfig            `yaml:"policy"`
	Actions       map[string]ActionConfig `yaml:"actions"`
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

// TokenIssuanceConfig gates the A1 raw-token export path.
//
// M1 uses a config-gate for A1; a future milestone may promote this to a
// build-tag for a stronger default-binary guarantee, per the approved plan at
// .omc/plans/gh-token-broker.md. When Enabled is false, the /token route is
// not registered on the mux at all (not merely 403), keeping the safe default
// footprint smaller.
type TokenIssuanceConfig struct {
	Enabled bool `yaml:"enabled"`
}

type PolicyConfig struct {
	// CostLimit bounds CEL runtime cost per evaluation (INV-7). A sane low
	// default guards against pathological operator expressions.
	CostLimit uint64 `yaml:"costLimit"`
	// MaxRepositories caps the size of a caller-supplied request.repositories
	// list before it is bound as a CEL activation variable (INV-7).
	MaxRepositories int    `yaml:"maxRepositories"`
	Rules           []Rule `yaml:"rules"`
}

// Rule is one policy rule. Only When is a CEL expression; Grant is static
// operator-authored config data. CEL only decides whether the operator's own
// pre-declared grant applies — it can never fabricate a novel grant from
// request data.
type Rule struct {
	Name    string `yaml:"name"`
	When    string `yaml:"when"`
	Grant   Grant  `yaml:"grant"`
	OnError string `yaml:"onError"` // skip | reject; defaults to reject (fail closed)
}

type Grant struct {
	Repositories []string          `yaml:"repositories"`
	Permissions  map[string]string `yaml:"permissions"`
}

// ActionConfig declares the GitHub permissions a built-in action requires.
// A2 scope comes ONLY from here (trusted proxy-side config), never from the
// request body or any runtime-fetched manifest (INV-6).
type ActionConfig struct {
	Permissions map[string]string `yaml:"permissions"`
}

// Load reads, schema-validates, and decodes the YAML config at path, applies
// defaults, then enforces semantic invariants (canonical permission keys,
// key material sourcing, action registry sanity).
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
	for i := range cfg.Policy.Rules {
		if cfg.Policy.Rules[i].OnError == "" {
			cfg.Policy.Rules[i].OnError = "reject" // fail closed by default
		}
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
	for _, r := range cfg.Policy.Rules {
		if seen[r.Name] {
			return fmt.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true
		if err := checkPermissions(fmt.Sprintf("rule %q grant", r.Name), r.Grant.Permissions); err != nil {
			return err
		}
	}
	for name, a := range cfg.Actions {
		if len(a.Permissions) == 0 {
			return fmt.Errorf("action %q: permissions must be non-empty", name)
		}
		if err := checkPermissions(fmt.Sprintf("action %q", name), a.Permissions); err != nil {
			return err
		}
	}
	return nil
}

// checkPermissions rejects any permission key not in the canonical table or
// any invalid level at load time (INV-10, fail-closed at startup).
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
			"tokenIssuance.enabled=true: the raw-token export path (A1) is active; ensure this is intended")
	}
	if len(c.Policy.Rules) == 0 {
		warnings = append(warnings,
			"policy.rules is empty: every request will be denied (deny-by-default)")
	}
	return warnings
}
