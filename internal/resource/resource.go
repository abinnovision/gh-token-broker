// Package resource provides parsing and validation for resource identifiers
// used to scope token requests, such as "repo:acme/app", "org:acme", or
// "enterprise:abi-group-gmbh".
package resource

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	maxOwnerLen = 39
	maxRepoLen  = 100
)

var (
	// ownerPattern matches GitHub user and organization logins: ASCII
	// alphanumerics separated by single hyphens.
	ownerPattern = regexp.MustCompile(`^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$`)
	repoPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	// slugPattern matches the enterprise slug rule used for the enterprise
	// issuer in the config package.
	slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// Kind identifies the type of resource a Resource refers to.
type Kind string

const (
	KindRepo       Kind = "repo"
	KindOrg        Kind = "org"
	KindEnterprise Kind = "enterprise"
)

// Resource represents a single parsed resource identifier.
type Resource struct {
	Kind  Kind
	Owner string // "acme" for repo:acme/app, "acme" for org:acme, slug for enterprise:slug
	Name  string // "app" for repo:acme/app, empty for org/enterprise
	Raw   string // canonical prefixed form, e.g. "repo:acme/app"
}

// Parse parses a single resource string into a Resource.
//
// Supported forms:
//   - "repo:owner/name"
//   - "org:name"
//   - "enterprise:slug"
//   - "owner/repo" (backward compat, rewritten to "repo:owner/repo")
func Parse(raw string) (Resource, error) {
	if raw == "" {
		return Resource{}, fmt.Errorf("resource: value must not be empty")
	}

	if prefix, remainder, ok := splitPrefix(raw); ok {
		switch prefix {
		case string(KindRepo):
			owner, name, err := splitOwnerName(remainder)
			if err != nil {
				return Resource{}, fmt.Errorf("resource: invalid repo value %q: %w", raw, err)
			}

			return Resource{
				Kind:  KindRepo,
				Owner: owner,
				Name:  name,
				Raw:   fmt.Sprintf("repo:%s/%s", owner, name),
			}, nil
		case string(KindOrg):
			owner, err := requireOwner(remainder)
			if err != nil {
				return Resource{}, fmt.Errorf("resource: invalid org value %q: %w", raw, err)
			}

			return Resource{
				Kind:  KindOrg,
				Owner: owner,
				Raw:   fmt.Sprintf("org:%s", owner),
			}, nil
		case string(KindEnterprise):
			owner, err := requireSlug(remainder)
			if err != nil {
				return Resource{}, fmt.Errorf("resource: invalid enterprise value %q: %w", raw, err)
			}

			return Resource{
				Kind:  KindEnterprise,
				Owner: owner,
				Raw:   fmt.Sprintf("enterprise:%s", owner),
			}, nil
		default:
			return Resource{}, fmt.Errorf("resource: unknown prefix %q in value %q", prefix, raw)
		}
	}

	// No known prefix; fall back to backward-compat "owner/repo" form.
	if strings.Contains(raw, "/") {
		owner, name, err := splitOwnerName(raw)
		if err != nil {
			return Resource{}, fmt.Errorf("resource: invalid value %q: %w", raw, err)
		}

		return Resource{
			Kind:  KindRepo,
			Owner: owner,
			Name:  name,
			Raw:   fmt.Sprintf("repo:%s/%s", owner, name),
		}, nil
	}

	return Resource{}, fmt.Errorf("resource: invalid value %q: expected a prefixed form (repo:, org:, enterprise:) or owner/repo", raw)
}

// splitPrefix checks whether raw has a known "<kind>:" prefix and, if so,
// returns the prefix and the remainder after the first colon.
func splitPrefix(raw string) (prefix string, remainder string, ok bool) {
	idx := strings.Index(raw, ":")
	if idx < 0 {
		return "", "", false
	}

	candidate := raw[:idx]
	switch candidate {
	case string(KindRepo), string(KindOrg), string(KindEnterprise):
		return candidate, raw[idx+1:], true
	default:
		return "", "", false
	}
}

// splitOwnerName splits an "owner/name" remainder and validates both parts.
func splitOwnerName(remainder string) (owner string, name string, err error) {
	owner, name, ok := strings.Cut(remainder, "/")
	if !ok {
		return "", "", fmt.Errorf("expected owner/name form")
	}

	if owner, err = requireOwner(owner); err != nil {
		return "", "", fmt.Errorf("owner: %w", err)
	}

	if name, err = requireRepoName(name); err != nil {
		return "", "", fmt.Errorf("name: %w", err)
	}

	return owner, name, nil
}

// requireOwner validates a GitHub user or organization login.
func requireOwner(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("value must not be empty")
	}

	if len(value) > maxOwnerLen {
		return "", fmt.Errorf("value must not exceed %d characters", maxOwnerLen)
	}

	if !ownerPattern.MatchString(value) {
		return "", fmt.Errorf("value must contain only ASCII letters, digits and single hyphens, and must not start or end with a hyphen")
	}

	return value, nil
}

// requireRepoName validates a GitHub repository name.
func requireRepoName(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("value must not be empty")
	}

	if len(value) > maxRepoLen {
		return "", fmt.Errorf("value must not exceed %d characters", maxRepoLen)
	}

	if value == "." || value == ".." {
		return "", fmt.Errorf("value must not be %q", value)
	}

	if !repoPattern.MatchString(value) {
		return "", fmt.Errorf("value must contain only ASCII letters, digits, '.', '_' and '-'")
	}

	return value, nil
}

// requireSlug validates an enterprise slug.
func requireSlug(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("value must not be empty")
	}

	if !slugPattern.MatchString(value) {
		return "", fmt.Errorf("value must be lowercase ASCII letters and digits separated by single hyphens")
	}

	return value, nil
}

// ParseAll parses all given values and enforces that they refer to a
// consistent set of resources: all resources must share the same Kind and
// Owner, and org/enterprise kinds allow only a single value.
func ParseAll(values []string) ([]Resource, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("resource: at least one value is required")
	}

	resources := make([]Resource, 0, len(values))

	for _, value := range values {
		r, err := Parse(value)
		if err != nil {
			return nil, err
		}

		resources = append(resources, r)
	}

	first := resources[0]

	for _, r := range resources[1:] {
		if r.Kind != first.Kind {
			return nil, fmt.Errorf(
				"resource: all resources must share the same kind, got %q and %q",
				first.Kind, r.Kind,
			)
		}

		if r.Owner != first.Owner {
			return nil, fmt.Errorf(
				"resource: all resources must share the same owner, got %q and %q",
				first.Owner, r.Owner,
			)
		}
	}

	if (first.Kind == KindOrg || first.Kind == KindEnterprise) && len(resources) > 1 {
		return nil, fmt.Errorf(
			"resource: only a single %s value is allowed, got %d", first.Kind, len(resources),
		)
	}

	return resources, nil
}

// Owner returns the common owner shared by all resources. It assumes
// resources was produced by ParseAll, which guarantees a non-empty slice
// with a shared owner.
func Owner(resources []Resource) string {
	return resources[0].Owner
}

// RepoFullNames returns "owner/repo" strings for all KindRepo resources. It
// returns nil if resources does not contain repo-kind resources.
func RepoFullNames(resources []Resource) []string {
	if len(resources) == 0 || resources[0].Kind != KindRepo {
		return nil
	}

	names := make([]string, 0, len(resources))
	for _, r := range resources {
		names = append(names, fmt.Sprintf("%s/%s", r.Owner, r.Name))
	}

	return names
}

// RepoShortNames returns the bare repo names for all KindRepo resources. It
// returns nil if resources does not contain repo-kind resources.
func RepoShortNames(resources []Resource) []string {
	if len(resources) == 0 || resources[0].Kind != KindRepo {
		return nil
	}

	names := make([]string, 0, len(resources))
	for _, r := range resources {
		names = append(names, r.Name)
	}

	return names
}

// RawStrings returns the canonical Raw form of each resource.
func RawStrings(resources []Resource) []string {
	raws := make([]string, 0, len(resources))
	for _, r := range resources {
		raws = append(raws, r.Raw)
	}

	return raws
}
