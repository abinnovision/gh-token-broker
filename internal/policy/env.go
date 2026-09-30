// Package policy compiles operator-authored CEL policies once at construction
// and evaluates caller/request context against them as an additive,
// default-reject allow set.
package policy

import (
	"reflect"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
)

// Variable names exposed to CEL. Nothing else is exposed — only verified OIDC
// claims and the normalized request context are policy-decidable.
const (
	VarCaller  = "caller"
	VarRequest = "request"
)

// NewEnv builds the CEL environment shared by all policy expressions.
//
// No string extension functions are registered, and compile rejects the
// standard startsWith, endsWith, contains and matches functions as well as
// ordering comparisons on caller or request, so operators can't write an
// unanchored match like caller.repository.startsWith("myorg/") that
// "myorg/repo-evil" would also satisfy. Claims and resources are compared
// with exact equality (==) and list membership (in [...]).
//
// caller is a map of the issuer's claims; compile restricts it to reads of
// declared claims. request is a native Go struct, so unknown field references
// fail policy compilation at startup.
func NewEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable(VarCaller, cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable(VarRequest, cel.ObjectType("policy.Request")),
		ext.NativeTypes(
			reflect.TypeOf(Request{}),
			ext.ParseStructTags(true),
		),
	)
}
