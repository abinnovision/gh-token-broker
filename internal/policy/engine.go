package policy

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

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

// Request is the normalized request context exposed to CEL.
type Request struct {
	Resources []string `cel:"resources"`
}

// Decision is the outcome of evaluating one request against every policy.
type Decision struct {
	// Allowed is true only when at least one policy matched and their combined
	// grant fully covers the required scope.
	Allowed bool
	// MatchedPolicies names every policy whose condition evaluated true.
	MatchedPolicies []string
	// SkippedPolicies names policies whose CEL evaluation failed at runtime.
	// They are logged and do not block matching policies.
	SkippedPolicies []string
	// Grant is the aggregate static grant from MatchedPolicies.
	Grant Grant
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
// offending policy. cel.CostLimit is applied to every program.
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
		prg, err := compile(env, p.Name, p.Condition, cfg.Policy.CostLimit)
		if err != nil {
			return nil, err
		}
		e.policies = append(e.policies, compiledPolicy{
			name:      p.Name,
			condition: prg,
			grant:     Grant{Permissions: p.Grant.Permissions},
		})
	}
	return e, nil
}

// compile checks the expression yields a bool and wires the per-program cost
// limit.
func compile(env *cel.Env, policy, expr string, costLimit uint64) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("policy %q: compile condition: %w", policy, iss.Err())
	}
	out := ast.OutputType()
	if out.Kind() != types.DynKind && out.Kind() != types.BoolKind {
		return nil, fmt.Errorf("policy %q: condition must evaluate to bool, got %s", policy, out)
	}
	prg, err := env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return nil, fmt.Errorf("policy %q: program condition: %w", policy, err)
	}
	return prg, nil
}

// Evaluate evaluates every policy without relying on configuration order.
// Every matching policy contributes to a combined static grant. A request is
// allowed only when that grant fully covers required. Runtime CEL failures are
// logged and skipped; no matching policy denies by default.
//
// It returns a non-nil error only for an operational rejection that must not
// be silently absorbed — specifically an oversized request.resources list,
// which must be rejected outright, never truncated.
func (e *Engine) Evaluate(in Input, required Scope) (Decision, error) {
	if err := e.checkListCaps(in.Request); err != nil {
		return Decision{}, err
	}

	vars := map[string]any{
		VarCaller:  in.Caller,
		VarRequest: in.Request,
	}

	decision := Decision{Grant: Grant{Permissions: map[string]string{}}}
	for _, p := range e.policies {
		matched, err := evalBool(p.condition, vars)
		if err != nil {
			e.logger.Warn("policy evaluation error", "policy", p.name, "error", err.Error())
			decision.SkippedPolicies = append(decision.SkippedPolicies, p.name)
			continue
		}
		if matched {
			decision.MatchedPolicies = append(decision.MatchedPolicies, p.name)
			mergePermissions(decision.Grant.Permissions, p.grant.Permissions)
		}
	}

	sort.Strings(decision.MatchedPolicies)
	sort.Strings(decision.SkippedPolicies)
	decision.Allowed = len(decision.MatchedPolicies) > 0 &&
		coversPermissions(required.Permissions, decision.Grant.Permissions)
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

// checkListCaps enforces the request.resources cap before the list is
// bound as a CEL activation value. Oversized lists are rejected, never
// truncated.
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
