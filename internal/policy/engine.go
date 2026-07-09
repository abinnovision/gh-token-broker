package policy

import (
	"fmt"
	"log/slog"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/abinnovision/gh-token-broker/internal/config"
)

// Grant is the operator-authored static scope a matched rule confers. It is a
// copy of the config grant, never derived from request data.
type Grant struct {
	Repositories []string
	Permissions  map[string]string
}

// Decision is the outcome of evaluating one request against the rule chain.
type Decision struct {
	// Matched is true iff some rule's `when` evaluated true (and did not
	// fail closed). When false, the request is denied (deny-by-default).
	Matched bool
	// RuleName is the matched rule's name, or "" when nothing matched.
	RuleName string
	// Grant is the matched rule's static grant; zero value when unmatched.
	Grant Grant
}

// Input carries the strictly-typed activation values for one evaluation.
// Request is nil for A2; Action is nil for A1. Nil maps are bound as empty
// maps so any rule expression evaluates without an unbound-variable error.
type Input struct {
	Caller   map[string]string
	Advisory map[string]string
	Request  map[string]any
	Action   map[string]any
}

type compiledRule struct {
	name    string
	when    cel.Program
	grant   Grant
	onError string // skip | reject
}

// Engine evaluates requests against the configured rule chain. Compiled
// cel.Programs are safe for concurrent use, so one Engine serves all requests.
type Engine struct {
	rules           []compiledRule
	maxRepositories int
	logger          *slog.Logger
}

// New compiles every rule's `when` expression ONCE from operator config
// (INV-7: never from request data) and fails fast on the first error, naming
// the offending rule. cel.CostLimit is applied to every program (INV-7).
func New(cfg *config.Config, logger *slog.Logger) (*Engine, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	e := &Engine{
		maxRepositories: cfg.Policy.MaxRepositories,
		logger:          logger,
	}
	for _, r := range cfg.Policy.Rules {
		prg, err := compile(env, r.Name, r.When, cfg.Policy.CostLimit)
		if err != nil {
			return nil, err
		}
		onError := r.OnError
		if onError == "" {
			onError = "reject"
		}
		e.rules = append(e.rules, compiledRule{
			name:    r.Name,
			when:    prg,
			grant:   Grant{Repositories: r.Grant.Repositories, Permissions: r.Grant.Permissions},
			onError: onError,
		})
	}
	return e, nil
}

// compile checks the expression yields a bool and wires the per-program cost
// limit.
func compile(env *cel.Env, rule, expr string, costLimit uint64) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("rule %q: compile when: %w", rule, iss.Err())
	}
	out := ast.OutputType()
	if out.Kind() != types.DynKind && out.Kind() != types.BoolKind {
		return nil, fmt.Errorf("rule %q: when must evaluate to bool, got %s", rule, out)
	}
	prg, err := env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return nil, fmt.Errorf("rule %q: program when: %w", rule, err)
	}
	return prg, nil
}

// Evaluate walks the rules in config order; the first rule whose `when` is true
// determines the grant (first-match-wins, which trivially satisfies INV-3: no
// union of grants across rules). No match denies (deny-by-default).
//
// It returns a non-nil error only for an operational rejection that must not be
// silently absorbed — specifically an oversized request.repositories list
// (INV-7): the caller MUST reject the request rather than truncate.
func (e *Engine) Evaluate(in Input) (Decision, error) {
	if err := e.checkListCaps(in.Request); err != nil {
		return Decision{}, err
	}

	vars := map[string]any{
		VarCaller:   nonNilStr(in.Caller),
		VarAdvisory: nonNilStr(in.Advisory),
		VarRequest:  nonNilAny(in.Request),
		VarAction:   nonNilAny(in.Action),
	}

	for _, r := range e.rules {
		matched, err := evalBool(r.when, vars)
		if err != nil {
			// Fail closed on a security rule: onError=reject halts the chain
			// and denies; onError=skip continues to the next rule.
			e.logger.Warn("rule evaluation error",
				"rule", r.name, "onError", r.onError, "error", err.Error())
			if r.onError == "reject" {
				return Decision{Matched: false, RuleName: r.name}, nil
			}
			continue
		}
		if matched {
			return Decision{Matched: true, RuleName: r.name, Grant: r.grant}, nil
		}
	}
	return Decision{Matched: false}, nil
}

// checkListCaps enforces INV-7's request.repositories cap BEFORE the list is
// bound as an activation variable. Oversized lists are rejected, never
// truncated.
func (e *Engine) checkListCaps(request map[string]any) error {
	if request == nil {
		return nil
	}
	repos, ok := request["repositories"]
	if !ok {
		return nil
	}
	list, ok := repos.([]string)
	if !ok {
		if anyList, ok2 := repos.([]any); ok2 {
			if len(anyList) > e.maxRepositories {
				return fmt.Errorf("request.repositories has %d entries, exceeds cap of %d",
					len(anyList), e.maxRepositories)
			}
		}
		return nil
	}
	if len(list) > e.maxRepositories {
		return fmt.Errorf("request.repositories has %d entries, exceeds cap of %d",
			len(list), e.maxRepositories)
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

func nonNilStr(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func nonNilAny(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
