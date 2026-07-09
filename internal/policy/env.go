// Package policy compiles operator-authored CEL rules once at construction and
// evaluates caller/request context against them, first-match-wins,
// default-reject.
package policy

import "github.com/google/cel-go/cel"

// Variable names exposed to CEL. Nothing else is exposed — only id-anchored,
// verified OIDC claims and the explicit request/action context are
// policy-decidable.
const (
	VarCaller   = "caller"          // verified id-anchored OIDC claims
	VarAdvisory = "caller_advisory" // advisory-only claims — see below
	VarRequest  = "request"         // caller-supplied desired scope for token issuance (untrusted)
	VarAction   = "action"          // dispatch target for workflow-dispatch (untrusted)
)

// NewEnv builds the CEL environment shared by all rule expressions.
//
// No string extension functions or contains/startsWith helpers are
// registered, so operators can't write an unanchored match like
// caller.repository.startsWith("myorg/") that "myorg/repo-evil" would also
// satisfy — only exact equality (==) and list membership (in [...]) are
// available.
//
// caller_advisory carries fork-influenceable, event-derived claims (ref,
// workflow, actor) for logging/inspection only. Rule authors must never use
// caller_advisory in an allow decision — CEL can't enforce that, so it's a
// code-review rule: reject any policy rule that reads caller_advisory.
//
// caller and caller_advisory are map<string,string>. request and action are
// map<string,dyn> because they carry heterogeneous shapes (repository lists,
// permission maps, action inputs).
func NewEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable(VarCaller, cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable(VarAdvisory, cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable(VarRequest, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(VarAction, cel.MapType(cel.StringType, cel.DynType)),
	)
}
