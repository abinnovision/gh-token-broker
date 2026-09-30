package policy

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/overloads"
	"cel.dev/cel-go/common/types"

	"github.com/abinnovision/gh-token-broker/internal/config"
	"github.com/abinnovision/gh-token-broker/internal/perm"
)

// Grant is the aggregate of the static permissions contributed by matching
// policies. It is never derived from request data.
type Grant struct {
	Permissions map[string]string
}

// Scope is the exact permission scope an endpoint requires for an operation.
// Repository authorization belongs in policy conditions.
type Scope struct {
	Permissions map[string]string
}

// Caller is the complete, verified OIDC identity exposed to CEL. Its fixed
// shape makes unknown claim references configuration errors at startup.
type Caller struct {
	Repository        string `cel:"repository"`
	RepositoryID      string `cel:"repository_id"`
	RepositoryOwner   string `cel:"repository_owner"`
	RepositoryOwnerID string `cel:"repository_owner_id"`
	JobWorkflowRef    string `cel:"job_workflow_ref"`
}

// Request is the normalized request context exposed to CEL. Callers set
// Resources; Evaluate binds Resource to each requested resource in turn and
// Resources to a list holding only that resource.
type Request struct {
	Resource string `cel:"resource"`
	// Resources is a deprecated alias for [Resource].
	Resources []string `cel:"resources"`
}

// Decision is the outcome of evaluating one request against every policy.
type Decision struct {
	// Allowed is true only when at least one resource was requested and every
	// requested resource is covered.
	Allowed bool
	// MatchedPolicies names every policy whose condition evaluated true for
	// at least one resource.
	MatchedPolicies []string
	// SkippedPolicies names policies whose CEL evaluation failed at runtime
	// for at least one resource. They are logged and do not block matching
	// policies.
	SkippedPolicies []string
	// Grants holds, per requested resource, the aggregate static grant of the
	// policies matching that resource.
	Grants map[string]Grant
	// UncoveredResources lists, sorted, the resources that no policy matched
	// or whose grant does not fully cover the required scope.
	UncoveredResources []string
}

// Input carries the strictly typed activation values for one evaluation.
type Input struct {
	Caller  Caller
	Request Request
}

type compiledPolicy struct {
	name      string
	condition cel.Program
	grant     Grant
}

// Engine evaluates requests against the configured policy set. Compiled
// cel.Programs are safe for concurrent use, so one Engine serves all requests.
type Engine struct {
	policies        []compiledPolicy
	maxRepositories int
	logger          *slog.Logger
}

// New compiles every policy condition once from operator config
// (never from request data) and fails fast on the first error, naming the
// offending policy. cel.CostLimit is applied to every program. Condition
// warnings are logged per policy.
func New(cfg *config.Config, logger *slog.Logger) (*Engine, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	e := &Engine{
		maxRepositories: cfg.Policy.MaxRepositories,
		logger:          logger,
	}
	for _, p := range cfg.Policies {
		prg, warnings, err := compile(env, p.Name, p.Condition, cfg.Policy.CostLimit)
		if err != nil {
			return nil, err
		}
		for _, w := range warnings {
			logger.Warn("policy condition warning", "policy", p.Name, "warning", w)
		}
		e.policies = append(e.policies, compiledPolicy{
			name:      p.Name,
			condition: prg,
			grant:     Grant{Permissions: p.Grant.Permissions},
		})
	}
	return e, nil
}

// compile checks the expression yields a bool, wires the per-program cost
// limit and returns the condition warnings of the checked AST.
func compile(env *cel.Env, policy, expr string, costLimit uint64) (cel.Program, []string, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, nil, fmt.Errorf("policy %q: compile condition: %w", policy, iss.Err())
	}
	out := ast.OutputType()
	if out.Kind() != types.DynKind && out.Kind() != types.BoolKind {
		return nil, nil, fmt.Errorf("policy %q: condition must evaluate to bool, got %s", policy, out)
	}
	prg, err := env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return nil, nil, fmt.Errorf("policy %q: program condition: %w", policy, err)
	}
	return prg, conditionWarnings(ast.NativeRep()), nil
}

// Condition warnings reported by conditionWarnings.
const (
	warnDeprecatedResources = "request.resources is deprecated, use request.resource"
	warnUnconstrained       = "condition (or one of its || branches) does not reference " +
		"request.resource, so the policy applies to every requested resource, including org: and enterprise:"
	warnResourcesShape = "size() or index access on request.resources: the list always has exactly one element"
)

// conditionWarnings inspects a checked condition for patterns that behave
// unexpectedly under per-resource evaluation.
func conditionWarnings(ast *celast.AST) []string {
	root := celast.NavigateAST(ast)
	var warnings []string
	if len(celast.MatchDescendants(root, requestFieldMatcher("resources"))) > 0 {
		warnings = append(warnings, warnDeprecatedResources)
	}
	if !constrainsResource(ast, root) {
		warnings = append(warnings, warnUnconstrained)
	}
	if len(celast.MatchDescendants(root, resourcesShapeMatcher)) > 0 {
		warnings = append(warnings, warnResourcesShape)
	}
	return warnings
}

// requestFieldMatcher matches the select expression request.<field>.
func requestFieldMatcher(field string) celast.ExprMatcher {
	return func(e celast.NavigableExpr) bool { return isRequestField(e, field) }
}

func isRequestField(e celast.Expr, field string) bool {
	if e.Kind() != celast.SelectKind {
		return false
	}
	sel := e.AsSelect()
	return sel.FieldName() == field && sel.Operand().Kind() == celast.IdentKind &&
		sel.Operand().AsIdent() == VarRequest
}

// resourcesShapeMatcher matches size() and index calls on request.resources.
func resourcesShapeMatcher(e celast.NavigableExpr) bool {
	if e.Kind() != celast.CallKind {
		return false
	}
	call := e.AsCall()
	switch call.FunctionName() {
	case overloads.Size, operators.Index, operators.OptIndex:
	default:
		return false
	}
	operands := call.Args()
	if call.IsMemberFunction() {
		operands = append([]celast.Expr{call.Target()}, operands...)
	}
	return slices.ContainsFunc(operands, func(op celast.Expr) bool {
		return isRequestField(op, "resources")
	})
}

// constrainsResource reports whether e can only be true when a subexpression
// referencing the resource holds: every || operand must constrain it, while
// one && operand suffices.
func constrainsResource(ast *celast.AST, e celast.Expr) bool {
	if e.Kind() == celast.CallKind {
		switch call := e.AsCall(); call.FunctionName() {
		case operators.LogicalOr:
			return !slices.ContainsFunc(call.Args(), func(arg celast.Expr) bool {
				return !constrainsResource(ast, arg)
			})
		case operators.LogicalAnd:
			return slices.ContainsFunc(call.Args(), func(arg celast.Expr) bool {
				return constrainsResource(ast, arg)
			})
		}
	}
	nav := celast.NavigateExpr(ast, e)
	return len(celast.MatchDescendants(nav, requestFieldMatcher("resource"))) > 0 ||
		len(celast.MatchDescendants(nav, requestFieldMatcher("resources"))) > 0
}

// Evaluate evaluates every policy once per distinct requested resource,
// without relying on configuration or resource order. The grants of all
// policies matching a resource combine into that resource's grant; grants
// never combine across resources. A request is allowed only when every
// resource has at least one matching policy and its grant fully covers
// required. Runtime CEL failures are logged and skipped; an empty resource
// list or a resource without a matching policy denies by default.
//
// It returns a non-nil error only for an operational rejection that must not
// be silently absorbed: an oversized request.resources list, which must be
// rejected outright, never truncated.
func (e *Engine) Evaluate(in Input, required Scope) (Decision, error) {
	if err := e.checkListCaps(in.Request); err != nil {
		return Decision{}, err
	}

	decision := Decision{Grants: map[string]Grant{}}
	matched := map[string]bool{}
	skipped := map[string]bool{}
	for _, r := range in.Request.Resources {
		if _, seen := decision.Grants[r]; seen {
			continue
		}
		vars := map[string]any{
			VarCaller:  in.Caller,
			VarRequest: Request{Resource: r, Resources: []string{r}},
		}
		grant := Grant{Permissions: map[string]string{}}
		covered := false
		for _, p := range e.policies {
			ok, err := evalBool(p.condition, vars)
			if err != nil {
				e.logger.Warn("policy evaluation error", "policy", p.name, "resource", r, "error", err.Error())
				skipped[p.name] = true
				continue
			}
			if ok {
				covered = true
				matched[p.name] = true
				mergePermissions(grant.Permissions, p.grant.Permissions)
			}
		}
		decision.Grants[r] = grant
		if !covered || !coversPermissions(required.Permissions, grant.Permissions) {
			decision.UncoveredResources = append(decision.UncoveredResources, r)
		}
	}

	sort.Strings(decision.UncoveredResources)
	decision.MatchedPolicies = slices.Sorted(maps.Keys(matched))
	decision.SkippedPolicies = slices.Sorted(maps.Keys(skipped))
	decision.Allowed = len(decision.Grants) > 0 && len(decision.UncoveredResources) == 0
	return decision, nil
}

func mergePermissions(destination, source map[string]string) {
	for key, level := range perm.Normalize(source) {
		existing, ok := destination[key]
		if !ok || perm.Satisfies(map[string]string{key: existing}, map[string]string{key: level}) {
			destination[key] = level
		}
	}
}

func coversPermissions(required, granted map[string]string) bool {
	if len(perm.Normalize(required)) != len(required) {
		return false
	}
	return perm.Satisfies(required, granted)
}

// checkListCaps enforces the resource cap on the full requested list,
// duplicates included, before any CEL evaluation. Oversized lists are
// rejected, never truncated.
func (e *Engine) checkListCaps(req Request) error {
	if len(req.Resources) > e.maxRepositories {
		return fmt.Errorf("request.resources has %d entries, exceeds cap of %d",
			len(req.Resources), e.maxRepositories)
	}
	return nil
}

func evalBool(prg cel.Program, vars map[string]any) (bool, error) {
	out, _, err := prg.Eval(vars)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression returned %s, want bool", out.Type().TypeName())
	}
	return b, nil
}
