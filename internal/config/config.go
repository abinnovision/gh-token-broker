// Package config loads and validates the proxy's YAML configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	root "github.com/abinnovision/gh-token-broker"
	"github.com/abinnovision/gh-token-broker/internal/perm"
)

// Config is the top-level proxy configuration.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	OIDC      OIDCConfig      `yaml:"oidc" jsonschema:"required"`
	GitHubApp GitHubAppConfig `yaml:"githubApp" jsonschema:"required"`
	Policy    PolicyConfig    `yaml:"policy"`
	Policies  []Policy        `yaml:"policies"`
}

type ServerConfig struct {
	Bind   string       `yaml:"bind" jsonschema:"default=:8080"`
	Issuer string       `yaml:"issuer" jsonschema:"description=The broker's own OAuth issuer identifier — a stable absolute https:// URL used as the RFC 8414 'issuer' and as the base of token_endpoint."`
	Proxy  *ProxyConfig `yaml:"proxy" jsonschema:"description=Reverse proxies in front of the broker. Absent means the client IP is the TCP peer address. The client IP is only used by policies with sourceCidrs."`
}

// ProxyConfig describes how to derive the client IP behind trusted reverse
// proxies. The header is only trustworthy when every trusted proxy appends the
// address of its peer to it and clients cannot reach the broker bypassing them
// (or TrustedProxies is set).
type ProxyConfig struct {
	Header         string   `yaml:"header" jsonschema:"default=X-Forwarded-For,description=Request header carrying the client IP. All header lines are joined and split on commas; the entry hops positions from the right is used. Use X-Real-Ip only with hops 1 and a proxy that overwrites it."`
	Hops           int      `yaml:"hops" jsonschema:"required,minimum=1,description=Number of trusted proxies in front of the broker. EVERY one of them must append the address of its peer to the header; an inner proxy that forwards without appending makes hops greater than 1 select a client-controlled entry. 1 selects the last entry."`
	TrustedProxies []string `yaml:"trustedProxies" jsonschema:"minItems=1,description=Optional CIDR ranges of the proxies. When set the header is only used if the TCP peer is inside them; any other peer is a direct client and its TCP address is used. Use it when the broker is reached both directly and through proxies. When unset the header is always used so the broker must be reachable only through the proxies."`
	// TrustedPrefixes holds TrustedProxies parsed and masked at load.
	TrustedPrefixes []netip.Prefix `yaml:"-"`
}

// DefaultProxyHeader is the header used when proxy.header is not set.
const DefaultProxyHeader = "X-Forwarded-For"

type OIDCConfig struct {
	Issuers          []OIDCIssuer `yaml:"issuers" jsonschema:"required,minItems=1,description=OIDC issuers whose tokens the broker accepts"`
	ClockSkewSeconds int          `yaml:"clockSkewSeconds" jsonschema:"default=60,minimum=0,maximum=300"`
}

// OIDCIssuer is one accepted OIDC issuer. After Load, Issuer, Algorithms,
// MaxTokenLifetimeSeconds and (for the preset) Claims and AuditClaims are
// resolved.
type OIDCIssuer struct {
	Name                    string              `yaml:"name" jsonschema:"required,pattern=^[a-z0-9-]+$,description=Identifier referenced by policies"`
	Preset                  string              `yaml:"preset" jsonschema:"enum=github,description=Built-in issuer definition; github supplies the issuer URL and the vetted GitHub Actions claims"`
	Issuer                  string              `yaml:"issuer" jsonschema:"description=Canonical https:// issuer URL matched exactly against the token iss claim. With preset github it may only name an enterprise issuer (https://token.actions.githubusercontent.com/ENTERPRISE-SLUG)"`
	Audience                string              `yaml:"audience" jsonschema:"required,minLength=1,description=REQUIRED broker-specific OIDC audience; tokens must carry exactly this single audience"`
	Algorithms              []string            `yaml:"algorithms" jsonschema:"minItems=1,enum=RS256,enum=RS384,enum=RS512,enum=ES256,enum=ES384,enum=ES512,enum=PS256,enum=PS384,enum=PS512,enum=EdDSA,description=Accepted signing algorithms (default [RS256])"`
	MaxTokenLifetimeSeconds int                 `yaml:"maxTokenLifetimeSeconds" jsonschema:"default=3600,minimum=1,maximum=86400,description=Upper bound on exp minus iat"`
	Claims                  []string            `yaml:"claims" jsonschema:"minItems=1,uniqueItems=true,description=Token claims exposed to policies as fields of caller. Required without a preset; not allowed with one"`
	Require                 map[string][]string `yaml:"require" jsonschema:"description=Claim values every token must match before policies run. Required without a preset"`
	// AuditClaims are token claims recorded in the audit log only. Set by the
	// preset, never by configuration.
	AuditClaims []string `yaml:"-"`
}

// IsPreset reports whether the issuer uses the GitHub Actions preset.
func (i OIDCIssuer) IsPreset() bool {
	return i.Preset == GitHubPreset
}

// PinsID reports whether require pins an ID claim of the GitHub preset.
func (i OIDCIssuer) PinsID() bool {
	for k := range i.Require {
		if slices.Contains(GitHubIDClaims(), k) {
			return true
		}
	}
	return false
}

const (
	// GitHubPreset is the preset name for GitHub Actions OIDC tokens.
	GitHubPreset = "github"
	// GitHubIssuerURL is the GitHub Actions issuer. Enterprises with a
	// customized issuer use GitHubIssuerURL + "/<enterprise-slug>".
	GitHubIssuerURL = "https://" + githubIssuerHost

	githubIssuerHost = "token.actions.githubusercontent.com"

	// maxTokenLifetimeLimit and maxClockSkewLimit (seconds) keep duration
	// arithmetic in range and stop skew from defeating the lifetime cap.
	maxTokenLifetimeLimit = 86400
	maxClockSkewLimit     = 300
)

// githubClaims lists the claims the GitHub preset exposes to policies. An
// identity claim names the repository, owner, workflow file or enterprise of
// the run, so comparing it with a fixed value pins the caller. The other
// claims only narrow a policy that already pins the caller; job_workflow_ref
// is among them because any repository can call a reusable workflow.
var githubClaims = []struct {
	name     string
	identity bool
}{
	{"repository", true},
	{"repository_id", true},
	{"repository_owner", true},
	{"repository_owner_id", true},
	{"job_workflow_ref", false},
	{"workflow_ref", true},
	{"workflow_sha", false},
	{"job_workflow_sha", false},
	{"sha", false},
	{"ref", false},
	{"ref_type", false},
	{"ref_protected", false},
	{"environment", false},
	{"environment_node_id", false},
	{"repository_visibility", false},
	{"runner_environment", false},
	{"enterprise", true},
	{"enterprise_id", true},
	{"issuer_scope", false},
	{"event_name", false},
	{"sub", false},
}

// GitHubClaims returns the claims the GitHub preset exposes to policies.
func GitHubClaims() []string {
	var names []string
	for _, c := range githubClaims {
		names = append(names, c.name)
	}
	return names
}

// GitHubIdentityClaims returns the GitHub preset claims that pin the caller.
func GitHubIdentityClaims() []string {
	var names []string
	for _, c := range githubClaims {
		if c.identity {
			names = append(names, c.name)
		}
	}
	return names
}

// GitHubIDClaims returns the GitHub preset identity claims that hold
// immutable IDs. Name claims can be reassigned after a rename or deletion.
func GitHubIDClaims() []string {
	var names []string
	for _, c := range githubClaims {
		if c.identity && strings.HasSuffix(c.name, "_id") {
			names = append(names, c.name)
		}
	}
	return names
}

// GitHubAuditClaims returns the claims the GitHub preset records in the audit
// log. They identify the workflow run and are never exposed to policies.
func GitHubAuditClaims() []string {
	return []string{"run_id", "run_number", "run_attempt", "check_run_id"}
}

var (
	issuerNamePattern     = regexp.MustCompile(`^[a-z0-9-]+$`)
	enterpriseSlugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

	// registeredClaims are verified by the broker itself and never exposed to
	// or pinned by configuration.
	registeredClaims = map[string]bool{"iss": true, "aud": true, "exp": true, "iat": true, "nbf": true}

	// allowedAlgorithms are the asymmetric JWS algorithms an issuer may use.
	allowedAlgorithms = map[string]bool{
		"RS256": true, "RS384": true, "RS512": true,
		"ES256": true, "ES384": true, "ES512": true,
		"PS256": true, "PS384": true, "PS512": true,
		"EdDSA": true,
	}
)

type GitHubAppConfig struct {
	AppID          int64  `yaml:"appId" jsonschema:"required,minimum=1"`
	PrivateKeyPath string `yaml:"privateKeyPath" jsonschema:"minLength=1,description=Path to the App private key PEM file. Never put raw key material in this YAML."`
	PrivateKeyEnv  string `yaml:"privateKeyEnv" jsonschema:"minLength=1,description=Name of an environment variable holding the App private key PEM."`
}

type PolicyConfig struct {
	CostLimit       uint64 `yaml:"costLimit" jsonschema:"default=10000,minimum=1"`
	MaxRepositories int    `yaml:"maxRepositories" jsonschema:"default=256,minimum=1"`
}

type Policy struct {
	Name      string `yaml:"name" jsonschema:"required,minLength=1"`
	Issuer    string `yaml:"issuer" jsonschema:"required,minLength=1,description=Name of the oidc.issuers entry whose tokens this policy applies to"`
	Condition string `yaml:"condition" jsonschema:"required,minLength=1,description=CEL expression evaluating to bool; evaluated once per requested resource with request.resource set to that resource (request.resources is a deprecated alias for [request.resource]). The policy contributes its grant to each resource it matches; every requested resource must be covered for the full scope"`
	Grant     Grant  `yaml:"grant" jsonschema:"required"`
	// SourceCIDRs optionally restricts the policy to callers whose client IP
	// lies in one of the ranges.
	SourceCIDRs []string `yaml:"sourceCidrs" jsonschema:"minItems=1,description=Optional CIDR ranges the client IP must fall in for the policy to apply. Absent means no restriction. The client IP is the TCP peer unless server.proxy is set."`
	// SourcePrefixes holds SourceCIDRs parsed and masked at load.
	SourcePrefixes []netip.Prefix `yaml:"-"`
}

// Permissions maps canonical GitHub App permission keys to their granted level.
type Permissions map[string]string

type Grant struct {
	Permissions Permissions `yaml:"permissions" jsonschema:"required"`
}

// Load reads, schema-validates, and decodes the YAML config at path, applies
// defaults, then enforces semantic invariants (issuer definitions, canonical
// permission keys, key material sourcing).
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
	if err := checkSingleIssuerShape(data); err != nil {
		return nil, err
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

// checkSingleIssuerShape rejects the single-issuer layout (oidc.issuer,
// oidc.audience, policies without issuer) with migration instructions, since
// the schema error alone does not explain what to change.
func checkSingleIssuerShape(data []byte) error {
	var doc struct {
		OIDC     map[string]any   `yaml:"oidc"`
		Policies []map[string]any `yaml:"policies"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// Malformed documents are reported by validateSchema.
		return nil
	}
	_, hasIssuer := doc.OIDC["issuer"]
	_, hasAudience := doc.OIDC["audience"]
	if hasIssuer || hasAudience {
		return errors.New("oidc.issuer and oidc.audience are not supported: move them into an oidc.issuers entry " +
			"(name: github, preset: github, audience: <audience>) and add issuer: github to every policy (see the migration notes in README.md)")
	}
	for i, p := range doc.Policies {
		if _, ok := p["issuer"]; !ok {
			name, _ := p["name"].(string)
			return fmt.Errorf("policy %q (policies[%d]): issuer is required; set it to the name of the oidc.issuers entry "+
				"whose tokens the policy applies to (issuer: github for the GitHub Actions preset)", name, i)
		}
	}
	return nil
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
	for i := range cfg.OIDC.Issuers {
		iss := &cfg.OIDC.Issuers[i]
		if iss.IsPreset() {
			if iss.Issuer == "" {
				iss.Issuer = GitHubIssuerURL
			}
			if len(iss.Claims) == 0 {
				iss.Claims = GitHubClaims()
			}
			iss.AuditClaims = GitHubAuditClaims()
		}
		if len(iss.Algorithms) == 0 {
			iss.Algorithms = []string{"RS256"}
		}
		if iss.MaxTokenLifetimeSeconds == 0 {
			iss.MaxTokenLifetimeSeconds = 3600
		}
	}
	if cfg.Server.Proxy != nil && cfg.Server.Proxy.Header == "" {
		cfg.Server.Proxy.Header = DefaultProxyHeader
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
	if len(cfg.OIDC.Issuers) == 0 {
		return fmt.Errorf("oidc.issuers must list at least one issuer")
	}
	issuerNames := map[string]bool{}
	issuerURLs := map[string]bool{}
	for _, iss := range cfg.OIDC.Issuers {
		if err := validateIssuer(iss); err != nil {
			return err
		}
		if issuerNames[iss.Name] {
			return fmt.Errorf("duplicate oidc issuer name %q", iss.Name)
		}
		issuerNames[iss.Name] = true
		if issuerURLs[iss.Issuer] {
			return fmt.Errorf("duplicate oidc issuer URL %q", iss.Issuer)
		}
		issuerURLs[iss.Issuer] = true
	}
	if cfg.OIDC.ClockSkewSeconds < 0 || cfg.OIDC.ClockSkewSeconds > maxClockSkewLimit {
		return fmt.Errorf("oidc.clockSkewSeconds must be between 0 and %d", maxClockSkewLimit)
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

	if err := validateProxy(cfg.Server.Proxy); err != nil {
		return err
	}

	seen := map[string]bool{}
	for i := range cfg.Policies {
		p := &cfg.Policies[i]
		if seen[p.Name] {
			return fmt.Errorf("duplicate policy name %q", p.Name)
		}
		seen[p.Name] = true
		if !issuerNames[p.Issuer] {
			return fmt.Errorf("policy %q: issuer %q is not configured in oidc.issuers", p.Name, p.Issuer)
		}
		if err := checkPermissions(fmt.Sprintf("policy %q grant", p.Name), p.Grant.Permissions); err != nil {
			return err
		}
		prefixes, err := parsePrefixes(p.SourceCIDRs)
		if err != nil {
			return fmt.Errorf("policy %q: sourceCidrs: %w", p.Name, err)
		}
		p.SourcePrefixes = prefixes
	}
	return nil
}

// parsePrefixes parses and masks CIDRs. IPv4-mapped IPv6 prefixes are
// rejected because client IPs are always unmapped and would never match.
func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, c := range cidrs {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		if prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("CIDR %q is an IPv4-mapped IPv6 prefix: write the IPv4 CIDR instead", c)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

// validateProxy checks the proxy settings after defaults are applied.
func validateProxy(p *ProxyConfig) error {
	if p == nil {
		return nil
	}
	if p.Hops < 1 {
		return errors.New("server.proxy.hops must be at least 1")
	}
	if !validHeaderName(p.Header) {
		return fmt.Errorf("server.proxy.header %q is not a valid HTTP header name", p.Header)
	}
	p.Header = http.CanonicalHeaderKey(p.Header)
	prefixes, err := parsePrefixes(p.TrustedProxies)
	if err != nil {
		return fmt.Errorf("server.proxy.trustedProxies: %w", err)
	}
	p.TrustedPrefixes = prefixes
	return nil
}

// validHeaderName reports whether name is a non-empty RFC 9110 token.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}

// validateIssuer enforces the rules for a single resolved issuer entry.
func validateIssuer(iss OIDCIssuer) error {
	where := fmt.Sprintf("oidc issuer %q", iss.Name)
	if !issuerNamePattern.MatchString(iss.Name) {
		return fmt.Errorf("%s: name must match %s", where, issuerNamePattern)
	}
	if iss.Preset != "" && !iss.IsPreset() {
		return fmt.Errorf("%s: unknown preset %q", where, iss.Preset)
	}
	if iss.Audience == "" {
		return fmt.Errorf("%s: audience is required (a broker-specific audience must be enforced)", where)
	}
	u, err := parseIssuerURL(iss.Issuer)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if iss.IsPreset() {
		if !slices.Equal(iss.Claims, GitHubClaims()) {
			return fmt.Errorf("%s: claims are fixed by preset %q and must not be set", where, GitHubPreset)
		}
		slug, ok := strings.CutPrefix(iss.Issuer, GitHubIssuerURL+"/")
		if iss.Issuer != GitHubIssuerURL && (!ok || !enterpriseSlugPattern.MatchString(slug)) {
			return fmt.Errorf("%s: preset %q only accepts issuer %s/<enterprise-slug>", where, GitHubPreset, GitHubIssuerURL)
		}
	} else {
		if u.Hostname() == githubIssuerHost {
			return fmt.Errorf("%s: GitHub Actions tokens must use preset: github", where)
		}
		if len(iss.Claims) == 0 {
			return fmt.Errorf("%s: claims must list the token claims policies may read", where)
		}
		if len(iss.Require) == 0 {
			return fmt.Errorf("%s: require must pin at least one tenant claim (for example an immutable namespace or organization ID)", where)
		}
	}
	for _, alg := range iss.Algorithms {
		if !allowedAlgorithms[alg] {
			return fmt.Errorf("%s: algorithm %q is not allowed (use RS, ES or PS 256/384/512 or EdDSA)", where, alg)
		}
	}
	if iss.MaxTokenLifetimeSeconds < 1 || iss.MaxTokenLifetimeSeconds > maxTokenLifetimeLimit {
		return fmt.Errorf("%s: maxTokenLifetimeSeconds must be between 1 and %d", where, maxTokenLifetimeLimit)
	}
	seen := map[string]bool{}
	for _, c := range iss.Claims {
		if err := checkClaimName(c); err != nil {
			return fmt.Errorf("%s: claims: %w", where, err)
		}
		if seen[c] {
			return fmt.Errorf("%s: claims: duplicate claim %q", where, c)
		}
		seen[c] = true
	}
	for _, c := range slices.Sorted(maps.Keys(iss.Require)) {
		if err := checkClaimName(c); err != nil {
			return fmt.Errorf("%s: require: %w", where, err)
		}
		values := iss.Require[c]
		if len(values) == 0 {
			return fmt.Errorf("%s: require %q must list at least one value", where, c)
		}
		if slices.Contains(values, "") {
			return fmt.Errorf("%s: require %q values must not be empty", where, c)
		}
	}
	return nil
}

// parseIssuerURL requires a canonical https:// URL, since issuers are matched
// against the token's iss claim by exact string comparison.
func parseIssuerURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("issuer is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Host != strings.ToLower(u.Host) ||
		u.Port() == "443" || strings.HasSuffix(u.Host, ":") || strings.HasSuffix(u.Hostname(), ".") || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") ||
		strings.HasSuffix(u.Path, "/") || u.String() != raw {
		return nil, fmt.Errorf("issuer %q must be a canonical https:// URL (lowercase host without trailing dot, no default port, trailing slash, query, fragment or userinfo)", raw)
	}
	return u, nil
}

// checkClaimName rejects empty, non-printable and broker-verified claim names.
func checkClaimName(name string) error {
	if name == "" {
		return errors.New("claim name must not be empty")
	}
	for _, r := range name {
		if r <= ' ' || r > '~' {
			return fmt.Errorf("claim %q must be printable ASCII without spaces", name)
		}
	}
	if registeredClaims[name] {
		return fmt.Errorf("claim %q is a registered token claim verified by the broker", name)
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

// sharedExampleAudience is a widely copied audience that Lint flags.
const sharedExampleAudience = "gh-token-broker"

// Lint returns non-fatal configuration warnings.
func (c *Config) Lint() []string {
	var warnings []string
	if len(c.Policies) == 0 {
		warnings = append(warnings,
			"policies is empty: every request will be denied (deny-by-default)")
	}
	referenced := map[string]bool{}
	for _, p := range c.Policies {
		referenced[p.Issuer] = true
	}
	for _, iss := range c.OIDC.Issuers {
		if !referenced[iss.Name] {
			warnings = append(warnings, fmt.Sprintf(
				"oidc issuer %q is not referenced by any policy: its tokens are always denied", iss.Name))
		}
		if iss.Audience == sharedExampleAudience {
			warnings = append(warnings, fmt.Sprintf(
				"oidc issuer %q uses the shared example audience %q: any broker with the same audience accepts the same tokens, "+
					"use a value unique to this deployment, such as its public URL", iss.Name, sharedExampleAudience))
		}
		if iss.IsPreset() && len(iss.Require) == 0 {
			warnings = append(warnings, fmt.Sprintf(
				"oidc issuer %q uses preset %q without require: tokens from any GitHub Actions workflow are accepted; "+
					"use require: {repository_owner_id: [...]}, or in every policy compare an ID claim (%s) with a fixed value "+
					"or use a caller-anchored resource. Name claims can be reassigned after a rename or deletion",
				iss.Name, GitHubPreset, strings.Join(GitHubIDClaims(), ", ")))
		}
		if iss.IsPreset() && len(iss.Require) > 0 && !iss.PinsID() {
			warnings = append(warnings, fmt.Sprintf(
				"oidc issuer %q has no ID claim in require: names can be reassigned and other claims do not identify the caller; "+
					"use repository_owner_id, repository_id or enterprise_id", iss.Name))
		}
	}
	return warnings
}
