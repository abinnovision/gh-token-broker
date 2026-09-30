package policy

// Condition warnings exposed for tests.
const (
	WarnDeprecatedResources = warnDeprecatedResources
	WarnUnconstrained       = warnUnconstrained
	WarnResourcesShape      = warnResourcesShape
)

// CompileWarnings compiles condition and returns its condition warnings.
func CompileWarnings(condition string) ([]string, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, err
	}
	_, warnings, err := compile(env, "test", condition, 10000)
	return warnings, err
}
