package policy

import "github.com/abinnovision/gh-token-broker/internal/config"

// Condition warnings exposed for tests.
const (
	WarnDeprecatedResources = warnDeprecatedResources
	WarnResourcesShape      = warnResourcesShape
)

// CompileWarnings compiles condition for a policy of iss and returns its
// condition warnings.
func CompileWarnings(iss config.OIDCIssuer, condition string) ([]string, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, err
	}
	_, warnings, err := compile(env, iss, "test", condition, 10000)
	return warnings, err
}
