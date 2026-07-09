// Package policy compiles operator-authored CEL rules once at construction and
// evaluates caller/request context against them, first-match-wins,
// default-reject.
package policy

import "github.com/google/cel-go/cel"

// Variable names exposed to CEL. Nothing else is exposed. This is the
// confused-deputy boundary (INV-4): only id-anchored, verified OIDC claims and
// the explicit request/action context are policy-decidable.
const (
	VarCaller   = "caller"          // map<string,string> of verified id-anchored OIDC claims
	VarAdvisory = "caller_advisory" // map<string,string> of advisory-only claims — see below
	VarRequest  = "request"         // A1 caller-supplied desired scope (untrusted)
	VarAction   = "action"          // A2 action target (untrusted)
)

// NewEnv builds the CEL environment shared by all rule expressions.
//
// Deliberate omissions, each a security decision:
//
//   - No string extension functions (ext.Strings) and no contains/startsWith
//     helpers are registered. This is intentional (INV-9): operators MUST match
//     id-anchored claims with exact equality (==) or list membership (in [...]),
//     never unanchored prefix/substring matching. Not exposing these helpers
//     avoids tempting operators into unanchored matches such as
//     caller.repository.startsWith("myorg/") which "myorg/repo-evil" would also
//     satisfy. CEL's own == and `in` are anchored by construction.
//
//   - caller_advisory carries fork-influenceable/event-derived claims (ref,
//     workflow, actor). It exists ONLY so an operator can log/inspect them; rule
//     authors are FORBIDDEN from using caller_advisory in the allow decision.
//     CEL cannot enforce "advisory only" at the type level, so this is enforced
//     by documentation, code review, and the README checklist — call it out in
//     review whenever a rule references caller_advisory.
//
// caller and caller_advisory are typed as map<string,string>. request and
// action are map<string,dyn> because they carry heterogeneous shapes
// (repositories list, permissions map, action inputs).
func NewEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable(VarCaller, cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable(VarAdvisory, cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable(VarRequest, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(VarAction, cel.MapType(cel.StringType, cel.DynType)),
	)
}
