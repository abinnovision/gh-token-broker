package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"

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

// Input carries the activation values for one evaluation. Issuer is the
// configured name of the issuer that verified the caller; only its policies
// are evaluated. Caller holds the verified claims of that issuer.
type Input struct {
	Issuer  string
	Caller  map[string]string
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
	// policies holds the compiled policies per issuer name.
	policies        map[string][]compiledPolicy
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
	issuers := make(map[string]config.OIDCIssuer, len(cfg.OIDC.Issuers))
	for _, iss := range cfg.OIDC.Issuers {
		issuers[iss.Name] = iss
	}
	e := &Engine{
		policies:        map[string][]compiledPolicy{},
		maxRepositories: cfg.Policy.MaxRepositories,
		logger:          logger,
	}
	for _, p := range cfg.Policies {
		iss, ok := issuers[p.Issuer]
		if !ok {
			return nil, fmt.Errorf("policy %q: unknown issuer %q", p.Name, p.Issuer)
		}
		prg, warnings, err := compile(env, iss, p.Name, p.Condition, cfg.Policy.CostLimit)
		if err != nil {
			return nil, err
		}
		for _, w := range warnings {
			logger.Warn("policy condition warning", "policy", p.Name, "warning", w)
		}
		e.policies[p.Issuer] = append(e.policies[p.Issuer], compiledPolicy{
			name:      p.Name,
			condition: prg,
			grant:     Grant{Permissions: p.Grant.Permissions},
		})
	}
	return e, nil
}

// compile checks the expression yields a bool and passes checkCondition for
// iss, wires the per-program cost limit and returns the condition warnings of
// the checked AST.
func compile(env *cel.Env, iss config.OIDCIssuer, policy, expr string, costLimit uint64) (cel.Program, []string, error) {
	ast, issues := env.Compile(expr)
	if issues.Err() != nil {
		return nil, nil, fmt.Errorf("policy %q: compile condition: %w", policy, issues.Err())
	}
	out := ast.OutputType()
	if out.Kind() != types.DynKind && out.Kind() != types.BoolKind {
		return nil, nil, fmt.Errorf("policy %q: condition must evaluate to bool, got %s", policy, out)
	}
	if err := checkCondition(ast.NativeRep(), iss); err != nil {
		return nil, nil, fmt.Errorf("policy %q: %w", policy, err)
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
	warnResourcesShape      = "size() or index access on request.resources: the list always has exactly one element"
)

// conditionWarnings inspects a checked condition for patterns that behave
// unexpectedly under per-resource evaluation.
func conditionWarnings(ast *celast.AST) []string {
	root := celast.NavigateAST(ast)
	var warnings []string
	if len(celast.MatchDescendants(root, requestFieldMatcher("resources"))) > 0 {
		warnings = append(warnings, warnDeprecatedResources)
	}
	if len(celast.MatchDescendants(root, resourcesShapeMatcher)) > 0 {
		warnings = append(warnings, warnResourcesShape)
	}
	return warnings
}

// checkCondition enforces the structural rules on the checked condition of a
// policy for iss:
//   - no comprehension variable shadows caller or request;
//   - no startsWith, endsWith, contains or matches call, and no ordering
//     comparison with an operand that reads caller or request;
//   - caller is only read as caller.<claim> or caller["<claim>"] with a
//     claim declared by iss;
//   - for non-preset issuers, request.resource is only compared with ==
//     against a string literal or with in against a list of string literals;
//   - the condition constrains the resource, and the caller through an
//     identity claim or a caller-anchored resource unless iss has require.
func checkCondition(ast *celast.AST, iss config.OIDCIssuer) error {
	root := celast.NavigateAST(ast)
	for _, c := range celast.MatchDescendants(root, celast.KindMatcher(celast.ComprehensionKind)) {
		comp := c.AsComprehension()
		for _, v := range []string{comp.IterVar(), comp.IterVar2(), comp.AccuVar()} {
			if v == VarCaller || v == VarRequest {
				return fmt.Errorf("comprehension variable %q shadows the policy variable", v)
			}
		}
	}
	for _, c := range celast.MatchDescendants(root, celast.KindMatcher(celast.CallKind)) {
		switch fn := c.AsCall().FunctionName(); fn {
		case overloads.StartsWith, overloads.EndsWith, overloads.Contains, overloads.Matches:
			return fmt.Errorf("%s() is not allowed, compare with == or in instead", fn)
		case operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals:
			if slices.ContainsFunc(c.Children(), func(arg celast.NavigableExpr) bool {
				return references(arg, VarCaller) || references(arg, VarRequest)
			}) {
				return errors.New("ordering comparisons (<, <=, >, >=) on caller or request are not allowed, " +
					"compare with == or in instead")
			}
		}
	}
	for _, ref := range celast.MatchDescendants(root, identMatcher(VarCaller)) {
		parent, ok := ref.Parent()
		if !ok {
			return errCallerAccess
		}
		claim, ok := callerClaim(parent)
		if !ok {
			return errCallerAccess
		}
		if !slices.Contains(iss.Claims, claim) {
			return fmt.Errorf("caller.%s is not a declared claim of issuer %q", claim, iss.Name)
		}
	}
	if !iss.IsPreset() {
		for _, ref := range celast.MatchDescendants(root, identMatcher(VarRequest)) {
			if !comparedToLiteral(ref) {
				return fmt.Errorf("issuer %q is not a preset, so request.resource may only be compared "+
					"with == against a string literal or with in against a list of string literals", iss.Name)
			}
		}
	}
	if !constrains(root, boundsResource) {
		return errors.New("condition (or one of its || branches) does not compare request.resource with == or in, " +
			"so the policy applies to every requested resource, including org: and enterprise: resources")
	}
	if identity := identityClaims(iss); len(iss.Require) == 0 && !constrains(root, boundsCaller(identity)) {
		return fmt.Errorf("condition (or one of its || branches) does not compare an identity claim (%s) with == or in "+
			"against a value that does not read caller, "+
			`or request.resource with a caller-anchored resource ("repo:" + caller.repository, `+
			`"repo:" + caller.repository_owner + "/<name>" or "org:" + caller.repository_owner), `+
			"and issuer %q has no require", strings.Join(identity, ", "), iss.Name)
	}
	return nil
}

// identityClaims returns the claims of iss that pin the caller when compared
// with a fixed value. Only the GitHub preset has any.
func identityClaims(iss config.OIDCIssuer) []string {
	if iss.IsPreset() {
		return config.GitHubIdentityClaims()
	}
	return nil
}

var errCallerAccess = errors.New(`caller may only be read as caller.<claim> or caller["<claim>"]`)

// requestFieldMatcher matches the select expression request.<field>.
func requestFieldMatcher(field string) celast.ExprMatcher {
	return func(e celast.NavigableExpr) bool { return isRequestField(e, field) }
}

func isRequestField(e celast.Expr, field string) bool {
	if e.Kind() != celast.SelectKind {
		return false
	}
	sel := e.AsSelect()
	return sel.FieldName() == field && isIdent(sel.Operand(), VarRequest)
}

// resourcesShapeMatcher matches size() and index calls on request.resources.
func resourcesShapeMatcher(e celast.NavigableExpr) bool {
	if e.Kind() != celast.CallKind {
		return false
	}
	call := e.AsCall()
	switch call.FunctionName() {
	case overloads.Size, operators.Index:
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

// isResourceRef reports whether e reads request.resource or its deprecated
// alias request.resources.
func isResourceRef(e celast.Expr) bool {
	return (isRequestField(e, "resource") || isRequestField(e, "resources")) && !e.AsSelect().IsTestOnly()
}

// identMatcher matches the identifier name.
func identMatcher(name string) celast.ExprMatcher {
	return func(e celast.NavigableExpr) bool { return isIdent(e, name) }
}

// isIdent reports whether e is the identifier name, with or without the
// leading dot of a root-scoped reference.
func isIdent(e celast.Expr, name string) bool {
	return e.Kind() == celast.IdentKind && strings.TrimPrefix(e.AsIdent(), ".") == name
}

func references(e celast.NavigableExpr, name string) bool {
	return len(celast.MatchDescendants(e, identMatcher(name))) > 0
}

func isStringLiteral(e celast.Expr) bool {
	_, ok := stringLiteral(e)
	return ok
}

// stringLiteral returns the value of e when e is a string literal.
func stringLiteral(e celast.Expr) (string, bool) {
	if e.Kind() != celast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().(types.String)
	return string(s), ok
}

// callerClaim returns the claim e reads when e is caller.<claim> or
// caller["<claim>"].
func callerClaim(e celast.Expr) (string, bool) {
	switch e.Kind() {
	case celast.SelectKind:
		if sel := e.AsSelect(); !sel.IsTestOnly() && isIdent(sel.Operand(), VarCaller) {
			return sel.FieldName(), true
		}
	case celast.CallKind:
		call := e.AsCall()
		if args := call.Args(); call.FunctionName() == operators.Index && len(args) == 2 &&
			isIdent(args[0], VarCaller) {
			return stringLiteral(args[1])
		}
	default:
	}
	return "", false
}

// comparedToLiteral reports whether the request identifier ref is read as the
// resource in an == comparison with a string literal, or as the left operand
// of in with a list of string literals.
func comparedToLiteral(ref celast.NavigableExpr) bool {
	sel, ok := ref.Parent()
	if !ok || !isResourceRef(sel) {
		return false
	}
	cmp, ok := sel.Parent()
	if !ok || cmp.Kind() != celast.CallKind {
		return false
	}
	args := cmp.Children()
	if len(args) != 2 {
		return false
	}
	switch cmp.AsCall().FunctionName() {
	case operators.Equals:
		other := args[0]
		if other.ID() == sel.ID() {
			other = args[1]
		}
		return isStringLiteral(other)
	case operators.In:
		return args[0].ID() == sel.ID() && args[1].Kind() == celast.ListKind &&
			!slices.ContainsFunc(args[1].AsList().Elements(), func(e celast.Expr) bool { return !isStringLiteral(e) })
	}
	return false
}

// constrains reports whether e can only be true when an == or in comparison
// accepted by bound, with its operands in either order, holds: every ||
// operand must constrain, while one && operand suffices. Negation, != and
// every other expression do not constrain.
func constrains(e celast.NavigableExpr, bound func(ref, other celast.NavigableExpr) bool) bool {
	if e.Kind() != celast.CallKind {
		return false
	}
	args := e.Children()
	switch e.AsCall().FunctionName() {
	case operators.LogicalOr:
		return !slices.ContainsFunc(args, func(arg celast.NavigableExpr) bool { return !constrains(arg, bound) })
	case operators.LogicalAnd:
		return slices.ContainsFunc(args, func(arg celast.NavigableExpr) bool { return constrains(arg, bound) })
	case operators.Equals, operators.In:
		return len(args) == 2 && (bound(args[0], args[1]) || bound(args[1], args[0]))
	}
	return false
}

// boundsResource accepts a comparison of the resource with an operand that
// does not read request.
func boundsResource(ref, other celast.NavigableExpr) bool {
	return isResourceRef(ref) && !references(other, VarRequest)
}

// boundsCaller returns a bound accepting a comparison of an identity claim
// with an operand that does not read caller, or of the resource with a
// caller-anchored resource or a list literal whose elements all are one. A
// comparison between two claims never counts, since it relates the token to
// itself rather than to a value chosen by the operator.
func boundsCaller(identity []string) func(ref, other celast.NavigableExpr) bool {
	return func(ref, other celast.NavigableExpr) bool {
		if claim, ok := callerClaim(ref); ok {
			return slices.Contains(identity, claim) && !references(other, VarCaller)
		}
		if !isResourceRef(ref) {
			return false
		}
		if other.Kind() == celast.ListKind {
			return !slices.ContainsFunc(other.AsList().Elements(), func(e celast.Expr) bool { return !callerAnchored(e) })
		}
		return callerAnchored(other)
	}
}

// callerAnchored reports whether e is a left-nested + chain of string
// literals and caller claims that starts with "repo:" + caller.repository,
// with "repo:" + caller.repository_owner + a literal starting with "/", or
// is exactly "org:" + caller.repository_owner. The owner of the resource is
// then always the caller's own.
func callerAnchored(e celast.Expr) bool {
	var ops []celast.Expr
	for e.Kind() == celast.CallKind && e.AsCall().FunctionName() == operators.Add && len(e.AsCall().Args()) == 2 {
		ops = append(ops, e.AsCall().Args()[1])
		e = e.AsCall().Args()[0]
	}
	ops = append(ops, e)
	slices.Reverse(ops)
	for _, op := range ops {
		if _, ok := callerClaim(op); !ok && !isStringLiteral(op) {
			return false
		}
	}
	literal := func(i int) string {
		if i >= len(ops) {
			return ""
		}
		s, _ := stringLiteral(ops[i])
		return s
	}
	claim := func(i int) string {
		if i >= len(ops) {
			return ""
		}
		c, _ := callerClaim(ops[i])
		return c
	}
	switch {
	case literal(0) == "repo:" && claim(1) == "repository":
		return true
	case literal(0) == "repo:" && claim(1) == "repository_owner":
		return strings.HasPrefix(literal(2), "/")
	case literal(0) == "org:" && claim(1) == "repository_owner":
		return len(ops) == 2
	}
	return false
}

// Evaluate evaluates every policy of in.Issuer once per distinct requested
// resource, without relying on configuration or resource order. An issuer
// without policies matches nothing and so denies. The grants of all
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
		for _, p := range e.policies[in.Issuer] {
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
