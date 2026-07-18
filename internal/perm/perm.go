// Package perm holds the canonical GitHub App permission-key allow-list and
// the per-key minimum-level intersection used to compute least-privilege
// scope. It is a leaf package (no internal imports) so config, githubapp and
// server can all depend on it without creating import cycles.
package perm

//go:generate bash -c "../../scripts/gen-catalog.sh > catalog_gen.go"

import "fmt"

// levels defines the permission lattice: read < write < admin. Any level
// string outside this table is invalid and treated as fail-closed (dropped).
var levels = map[string]int{
	"read":  1,
	"write": 2,
	"admin": 3,
}

// Canonical is the allow-list of GitHub App permission keys this proxy
// supports. Any permission key NOT in this table — whether it appears in a
// request or in a policy/action grant — is dropped (fail closed), never passed
// through to GitHub. This is a deliberately conservative starter set; extend
// it as new permissions are needed (and add a config-load test for the new
// key). Names mirror GitHub's installation-token permission field names.
var Canonical = map[string]bool{
	"actions":           true,
	"administration":         true,
	"checks":                 true,
	"contents":               true,
	"deployments":            true,
	"environments":           true,
	"issues":                 true,
	"metadata":               true,
	"packages":               true,
	"pages":                  true,
	"pull_requests":          true,
	"repository_hooks":       true,
	"repository_projects":    true,
	"secret_scanning_alerts": true,
	"secrets":                true,
	"security_events":        true,
	"statuses":               true,
	"vulnerability_alerts":   true,
	"workflows":              true,
}

// ValidKey reports whether k is a supported (canonical) permission key.
func ValidKey(k string) bool { return Canonical[k] }

// ValidLevel reports whether level is a known permission level.
func ValidLevel(level string) bool {
	_, ok := levels[level]
	return ok
}

// levelName returns the canonical string for a numeric level.
func levelName(n int) string {
	for name, v := range levels {
		if v == n {
			return name
		}
	}
	return ""
}

// Normalize returns a copy of in containing only entries whose key is in the
// canonical table AND whose level is valid. Everything else is dropped
// (fail-closed). A nil input yields an empty map.
func Normalize(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if !Canonical[k] {
			continue
		}
		if !ValidLevel(v) {
			continue
		}
		out[k] = v
	}
	return out
}

// Intersect computes the per-key minimum-level intersection across every
// input. A key survives only if it is present (and canonical/valid) in EVERY
// input; its resulting level is the minimum across inputs. This is never a
// naive set intersection and never a union: a key absent from any input is
// absent from the result. Each input is normalized first, so unknown keys and
// invalid levels can never leak through. With zero inputs the result is
// empty.
func Intersect(inputs ...map[string]string) map[string]string {
	if len(inputs) == 0 {
		return map[string]string{}
	}
	normalized := make([]map[string]string, len(inputs))
	for i, in := range inputs {
		normalized[i] = Normalize(in)
	}
	result := map[string]string{}
	for k, v := range normalized[0] {
		minLevel := levels[v]
		present := true
		for _, other := range normalized[1:] {
			ov, ok := other[k]
			if !ok {
				present = false
				break
			}
			if levels[ov] < minLevel {
				minLevel = levels[ov]
			}
		}
		if !present {
			continue
		}
		result[k] = levelName(minLevel)
	}
	return result
}

// Satisfies reports whether granted covers every key in required at a level
// that is at least as high (read < write < admin). A key present in required
// but missing from granted, or present at a lower level, fails the check.
// Both inputs are normalized first. An empty/nil required is trivially
// satisfied.
func Satisfies(required, granted map[string]string) bool {
	g := Normalize(granted)
	for k, v := range Normalize(required) {
		gv, ok := g[k]
		if !ok || levels[gv] < levels[v] {
			return false
		}
	}
	return true
}

// LevelOrd returns the numeric ordinal for a permission level string (read=1,
// write=2, admin=3). Unknown levels return 0.
func LevelOrd(level string) int {
	return levels[level]
}

// Gaps reports, for each key in required that granted fails to satisfy, a
// human-readable reason: either the key is missing from granted entirely, or
// granted's level for that key is below what's required. Both inputs are
// normalized first, mirroring Satisfies. Returns nil when required is fully
// satisfied by granted.
func Gaps(required, granted map[string]string) map[string]string {
	r := Normalize(required)
	g := Normalize(granted)
	gaps := map[string]string{}
	for k, v := range r {
		gv, ok := g[k]
		if !ok {
			gaps[k] = fmt.Sprintf("need %s, not granted", v)
		} else if levels[gv] < levels[v] {
			gaps[k] = fmt.Sprintf("need %s, have %s", v, gv)
		}
	}
	if len(gaps) == 0 {
		return nil
	}
	return gaps
}

// ValidKeyLevel reports whether key is a canonical permission key and level is
// valid for that specific key per the GitHub API catalog.
func ValidKeyLevel(key, level string) bool {
	if !Canonical[key] {
		return false
	}
	allowed, ok := Catalog[key]
	if !ok {
		return ValidLevel(level)
	}
	for _, l := range allowed {
		if l == level {
			return true
		}
	}
	return false
}
