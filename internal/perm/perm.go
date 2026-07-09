// Package perm holds the canonical GitHub App permission-key allow-list and
// the per-key minimum-level intersection used to compute least-privilege
// scope. It is a leaf package (no internal imports) so config, githubapp and
// server can all depend on it without creating import cycles.
package perm

// levels defines the permission lattice: read < write < admin. Any level
// string outside this table is invalid and treated as fail-closed (dropped).
var levels = map[string]int{
	"read":  1,
	"write": 2,
	"admin": 3,
}

// Canonical is the allow-list of GitHub App permission keys this proxy
// supports. Any permission key NOT in this table — whether it appears in a
// request or in a rule/action grant — is dropped (fail closed), never passed
// through to GitHub. This is a deliberately conservative starter set; extend
// it as new permissions are needed (and add a config-load test for the new
// key). Names mirror GitHub's installation-token permission field names.
var Canonical = map[string]bool{
	"actions":              true,
	"actions_variables":    true,
	"administration":       true,
	"checks":               true,
	"contents":             true,
	"deployments":          true,
	"environments":         true,
	"issues":               true,
	"metadata":             true,
	"packages":             true,
	"pages":                true,
	"pull_requests":        true,
	"repository_hooks":     true,
	"repository_projects":  true,
	"secret_scanning_alerts": true,
	"secrets":              true,
	"security_events":      true,
	"statuses":             true,
	"vulnerability_alerts": true,
	"workflows":            true,
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
// input (INV-2). A key survives only if it is present (and canonical/valid)
// in EVERY input; its resulting level is the minimum across inputs. This is
// never a naive set intersection and never a union: a key absent from any
// input is absent from the result. Each input is normalized first, so unknown
// keys and invalid levels can never leak through (INV-10). With zero inputs
// the result is empty.
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
