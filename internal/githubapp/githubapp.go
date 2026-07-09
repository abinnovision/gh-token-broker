// Package githubapp signs App JWTs, discovers installations, and mints
// least-privilege scoped installation access tokens. It is the single
// chokepoint through which both A1 and A2 pass; the INV-1 fail-closed guard
// lives on MintScopedToken, immediately before the GitHub API call.
package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v66/github"

	"github.com/abinnovision/gh-token-broker/internal/config"
	"github.com/abinnovision/gh-token-broker/internal/perm"
)

// defaultBaseURL is GitHub's REST API base.
const defaultBaseURL = "https://api.github.com"

// ErrEmptyScope is returned by MintScopedToken when the computed scope is
// empty. GitHub treats an absent repository/permission set as "all repos"/"all
// permissions", so an empty computed scope from a bug would silently escalate
// to a full-installation token. We fail closed instead (INV-1).
var ErrEmptyScope = errors.New("githubapp: refusing to mint token with empty repository or permission scope")

// IntersectPermissions is the per-key minimum-level permission intersection
// (INV-2). It is re-exported from the leaf perm package so the intersection
// math has a single implementation shared by config validation, the policy
// server, and this package.
var IntersectPermissions = perm.Intersect

// ScopedToken is a minted installation access token and its effective scope.
type ScopedToken struct {
	Token        string
	ExpiresAt    time.Time
	Permissions  map[string]string
	Repositories []string
}

// Client mints scoped tokens using the App's JWT. It is safe for concurrent
// use.
type Client struct {
	appID      int64
	apps       *github.Client // authenticated with the App JWT
	httpClient *http.Client   // App-JWT client used for the raw token POST
	baseURL    string
	logger     *slog.Logger
}

// New builds a Client from the App config, loading the private key from the
// configured file path or environment variable. The raw key material is never
// logged and never returned.
func New(cfg config.GitHubAppConfig, logger *slog.Logger) (*Client, error) {
	pem, err := loadPrivateKey(cfg)
	if err != nil {
		return nil, err
	}
	appsTransport, err := ghinstallation.NewAppsTransport(http.DefaultTransport, cfg.AppID, pem)
	if err != nil {
		return nil, fmt.Errorf("githubapp: build app transport: %w", err)
	}
	httpClient := &http.Client{Transport: appsTransport, Timeout: 30 * time.Second}
	return &Client{
		appID:      cfg.AppID,
		apps:       github.NewClient(httpClient),
		httpClient: httpClient,
		baseURL:    defaultBaseURL,
		logger:     logger,
	}, nil
}

func loadPrivateKey(cfg config.GitHubAppConfig) ([]byte, error) {
	switch {
	case cfg.PrivateKeyPath != "":
		data, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("githubapp: read private key file: %w", err)
		}
		return data, nil
	case cfg.PrivateKeyEnv != "":
		v := os.Getenv(cfg.PrivateKeyEnv)
		if v == "" {
			return nil, fmt.Errorf("githubapp: env %q is empty", cfg.PrivateKeyEnv)
		}
		return []byte(v), nil
	default:
		return nil, errors.New("githubapp: no private key source configured")
	}
}

// Mint resolves the installation for owner, intersects the requested
// permissions with the installation's actual granted ceiling, and mints a
// scoped token. repos are "owner/repo" names; every entry must share owner.
//
// The installation's real granted permissions are fetched at runtime and used
// as the app ceiling (defense in depth on top of GitHub's own server-side
// rejection), rather than trusting static config for the ceiling.
func (c *Client) Mint(ctx context.Context, owner string, repos []string, perms map[string]string) (ScopedToken, error) {
	inst, err := c.resolveInstallation(ctx, owner)
	if err != nil {
		return ScopedToken{}, err
	}
	ceiling := permMap(inst.GetPermissions())
	finalPerms := perm.Intersect(perms, ceiling)

	shortNames := make([]string, 0, len(repos))
	for _, full := range repos {
		o, name, ok := splitRepo(full)
		if !ok {
			return ScopedToken{}, fmt.Errorf("githubapp: invalid repository %q (want owner/repo)", full)
		}
		if !strings.EqualFold(o, owner) {
			return ScopedToken{}, fmt.Errorf("githubapp: repository %q is not under owner %q", full, owner)
		}
		shortNames = append(shortNames, name)
	}
	return c.MintScopedToken(ctx, inst.GetID(), shortNames, finalPerms)
}

// resolveInstallation finds the App installation for owner, trying the
// organization endpoint first and falling back to the user endpoint.
func (c *Client) resolveInstallation(ctx context.Context, owner string) (*github.Installation, error) {
	if inst, _, err := c.apps.Apps.FindOrganizationInstallation(ctx, owner); err == nil {
		return inst, nil
	}
	inst, _, err := c.apps.Apps.FindUserInstallation(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf("githubapp: no installation found for owner %q: %w", owner, err)
	}
	return inst, nil
}

// tokenRequest is the POST body for the installation access-token endpoint.
type tokenRequest struct {
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
}

// tokenResponse is the subset of GitHub's response we consume.
type tokenResponse struct {
	Token        string            `json:"token"`
	ExpiresAt    time.Time         `json:"expires_at"`
	Permissions  map[string]string `json:"permissions"`
	Repositories []struct {
		Name string `json:"name"`
	} `json:"repositories"`
}

// MintScopedToken mints a fresh installation access token scoped to repoNames
// (short repository names, owner implied by the installation) and perms.
//
// INV-1 fail-closed guard: this function refuses (returning ErrEmptyScope,
// never calling GitHub) if repoNames or perms is empty/nil. An empty scope
// would cause GitHub to mint a full-installation token. This is the single
// chokepoint both A1 and A2 pass through — the assertion is over the final
// computed artifact, not an independent recomputation.
//
// INV-11: no token caching in M1 — a fresh token is minted on every call.
func (c *Client) MintScopedToken(ctx context.Context, installationID int64, repoNames []string, perms map[string]string) (ScopedToken, error) {
	if len(repoNames) == 0 || len(perms) == 0 {
		return ScopedToken{}, ErrEmptyScope
	}

	body, err := json.Marshal(tokenRequest{Repositories: repoNames, Permissions: perms})
	if err != nil {
		return ScopedToken{}, fmt.Errorf("githubapp: encode token request: %w", err)
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return ScopedToken{}, fmt.Errorf("githubapp: build token request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ScopedToken{}, fmt.Errorf("githubapp: mint token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return ScopedToken{}, fmt.Errorf("githubapp: token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return ScopedToken{}, fmt.Errorf("githubapp: decode token response: %w", err)
	}
	names := make([]string, 0, len(tr.Repositories))
	for _, r := range tr.Repositories {
		names = append(names, r.Name)
	}
	return ScopedToken{
		Token:        tr.Token,
		ExpiresAt:    tr.ExpiresAt,
		Permissions:  tr.Permissions,
		Repositories: names,
	}, nil
}

// permMap converts a go-github InstallationPermissions struct to a
// map[string]string by JSON round-trip. Nil (omitempty) fields drop out, so
// the result contains exactly the permissions the installation actually grants.
func permMap(p *github.InstallationPermissions) map[string]string {
	if p == nil {
		return map[string]string{}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return map[string]string{}
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]string{}
	}
	return m
}

func splitRepo(full string) (owner, repo string, ok bool) {
	parts := strings.SplitN(full, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
