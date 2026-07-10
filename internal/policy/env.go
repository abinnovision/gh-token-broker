// Package policy compiles operator-authored CEL policies once at construction
// and evaluates caller/request context against them as an additive,
// default-reject allow set.
package policy

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// Variable names exposed to CEL. Nothing else is exposed — only verified OIDC
// claims and the normalized request context are policy-decidable.
const (
	VarCaller  = "caller"
	VarRequest = "request"
)

// NewEnv builds the CEL environment shared by all policy expressions.
//
// No string extension functions or contains/startsWith helpers are
// registered, so operators can't write an unanchored match like
// caller.repository.startsWith("myorg/") that "myorg/repo-evil" would also
// satisfy — only exact equality (==) and list membership (in [...]) are
// available.
//
// caller and request are native Go structs, so unknown field references fail
// policy compilation at startup. request.workflow_dispatch is an optional
// additive field that is populated only for workflow-dispatch requests.
func NewEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.OptionalTypes(),
		cel.Variable(VarCaller, cel.ObjectType("policy.Caller")),
		cel.Variable(VarRequest, cel.ObjectType("policy.Request")),
		ext.NativeTypes(
			reflect.TypeOf(Caller{}),
			reflect.TypeOf(Request{}),
			reflect.TypeOf(WorkflowDispatch{}),
			ext.ParseStructTags(true),
		),
	)
}
