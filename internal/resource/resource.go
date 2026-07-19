// Package resource provides parsing and validation for resource identifiers
// used to scope token requests, such as "repo:acme/app", "org:acme", or
// "enterprise:abi-group-gmbh".
package resource

import (
	"fmt"
	"strings"
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
			owner, err := requireSimpleName(remainder)
			if err != nil {
				return Resource{}, fmt.Errorf("resource: invalid org value %q: %w", raw, err)
			}

			return Resource{
				Kind:  KindOrg,
				Owner: owner,
				Raw:   fmt.Sprintf("org:%s", owner),
			}, nil
		case string(KindEnterprise):
			owner, err := requireSimpleName(remainder)
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

// splitOwnerName splits a "owner/name" remainder, requiring both parts to be
// non-empty.
func splitOwnerName(remainder string) (owner string, name string, err error) {
	idx := strings.Index(remainder, "/")
	if idx < 0 {
		return "", "", fmt.Errorf("expected owner/name form")
	}

	owner = remainder[:idx]
	name = remainder[idx+1:]

	if owner == "" || name == "" {
		return "", "", fmt.Errorf("owner and name must not be empty")
	}

	return owner, name, nil
}

// requireSimpleName validates a remainder that must be non-empty and must
// not contain a slash (used for org and enterprise values).
func requireSimpleName(remainder string) (string, error) {
	if remainder == "" {
		return "", fmt.Errorf("value must not be empty")
	}

	if strings.Contains(remainder, "/") {
		return "", fmt.Errorf("value must not contain '/'")
	}

	return remainder, nil
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
