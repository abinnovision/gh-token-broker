package policy_test

import (
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"sync"
	"testing"

	celast "cel.dev/cel-go/common/ast"

	"github.com/abinnovision/gh-token-broker/internal/config"
	"github.com/abinnovision/gh-token-broker/internal/policy"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

var (
	// pinnedGitHub is the default test issuer. Its require pin means
	// policies only have to constrain the resource.
	pinnedGitHub = config.OIDCIssuer{
		Name: "github", Preset: config.GitHubPreset, Claims: config.GitHubClaims(),
		Require: map[string][]string{"repository_owner_id": {"1"}},
	}
	openGitHub = config.OIDCIssuer{Name: "github", Preset: config.GitHubPreset, Claims: config.GitHubClaims()}
	gitlab     = config.OIDCIssuer{
		Name: "gitlab", Issuer: "https://gitlab.example.com", Claims: []string{"sub", "project_path"},
		Require: map[string][]string{"namespace_id": {"4711"}},
	}
	// openGeneric is a non-preset issuer without require, which config
	// validation rejects; none of its claims pins the caller.
	openGeneric = config.OIDCIssuer{Name: "gitlab", Issuer: "https://gitlab.example.com", Claims: []string{"sub", "project_path"}}
)

// newEngine fills in defaults: cost and list limits, pinnedGitHub as the
// only issuer and as the issuer of policies without one.
func newEngine(cfg *config.Config) (*policy.Engine, error) {
	if cfg.Policy.CostLimit == 0 {
		cfg.Policy.CostLimit = 10000
	}
	if cfg.Policy.MaxRepositories == 0 {
		cfg.Policy.MaxRepositories = 256
	}
	if len(cfg.OIDC.Issuers) == 0 {
		cfg.OIDC.Issuers = []config.OIDCIssuer{pinnedGitHub}
	}
	for i := range cfg.Policies {
		if cfg.Policies[i].Issuer == "" {
			cfg.Policies[i].Issuer = pinnedGitHub.Name
		}
	}
	return policy.New(cfg, discard())
}

func mustEngine(t *testing.T, cfg *config.Config) *policy.Engine {
	t.Helper()
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return e
}

func caller(repository, owner string) map[string]string {
	return map[string]string{"repository": repository, "repository_owner": owner}
}

func input(c map[string]string, resources ...string) policy.Input {
	return policy.Input{Issuer: pinnedGitHub.Name, Caller: c, Request: policy.Request{Resources: resources}}
}

func scope(permissions map[string]string) policy.Scope {
	return policy.Scope{Permissions: permissions}
}

func grantPolicy(name, condition string, permissions map[string]string) config.Policy {
	return config.Policy{Name: name, Condition: condition, Grant: config.Grant{Permissions: permissions}}
}

func evaluate(t *testing.T, e *policy.Engine, required map[string]string, resources ...string) policy.Decision {
	t.Helper()
	d, err := e.Evaluate(input(caller("acme/app", "acme"), resources...), scope(required))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDefaultRejectWhenNoPolicyMatches(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{{
		Name: "owner", Condition: `caller.repository_owner == "acme" && request.resource == "repo:acme/app"`,
		Grant: config.Grant{Permissions: map[string]string{"contents": "read"}},
	}}})
	d, err := e.Evaluate(input(caller("acme/app", "someone-else"), "repo:acme/app"), scope(map[string]string{"contents": "read"}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed || len(d.MatchedPolicies) != 0 {
		t.Fatalf("expected default reject, got %+v", d)
	}
}

func TestMatchingPoliciesCombinePermissionsRegardlessOfOrder(t *testing.T) {
	policies := []config.Policy{
		grantPolicy("contents-read", `request.resource == "repo:acme/app"`, map[string]string{"contents": "read"}),
		grantPolicy("contents-write", `request.resource == "repo:acme/app"`, map[string]string{"contents": "write"}),
	}
	required := scope(map[string]string{"contents": "write"})

	forward, err := mustEngine(t, &config.Config{Policies: policies}).
		Evaluate(input(caller("acme/app", "acme"), "repo:acme/app"), required)
	if err != nil {
		t.Fatal(err)
	}
	backward, err := mustEngine(t, &config.Config{Policies: []config.Policy{policies[1], policies[0]}}).
		Evaluate(input(caller("acme/app", "acme"), "repo:acme/app"), required)
	if err != nil {
		t.Fatal(err)
	}
	if !forward.Allowed || !backward.Allowed || !reflect.DeepEqual(forward.Grants, backward.Grants) {
		t.Fatalf("combined grant must be allowed and independent of policy order: forward=%+v backward=%+v", forward, backward)
	}
	if !reflect.DeepEqual(forward.Grants["repo:acme/app"].Permissions, map[string]string{"contents": "write"}) {
		t.Fatalf("wrong aggregate grant: %+v", forward.Grants)
	}
}

func TestCombinedPoliciesMustFullyCoverPermissions(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{{
		Name: "contents-read", Condition: `request.resource == "repo:acme/app"`,
		Grant: config.Grant{Permissions: map[string]string{"contents": "read"}},
	}}})
	for _, required := range []policy.Scope{
		scope(map[string]string{"contents": "write"}),
		scope(map[string]string{"issues": "read"}),
	} {
		d, err := e.Evaluate(input(caller("acme/app", "acme"), "repo:acme/app"), required)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed {
			t.Fatalf("partially covered permissions must be denied: %+v", d)
		}
	}
}

func TestConditionMustAuthorizeRequestedRepositories(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{{
		Name:      "own-repository",
		Condition: `request.resource == "repo:" + caller.repository`,
		Grant:     config.Grant{Permissions: map[string]string{"contents": "read"}},
	}}})
	for _, resources := range [][]string{{"repo:acme/app"}, {"repo:acme/other"}} {
		d, err := e.Evaluate(input(caller("acme/app", "acme"), resources...), scope(map[string]string{"contents": "read"}))
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed != (resources[0] == "repo:acme/app") {
			t.Fatalf("repository authorization must come from condition: resources=%v decision=%+v", resources, d)
		}
	}
}

func TestConditionMustAuthorizeOrgKindResources(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{{
		Name:      "own-org",
		Condition: `request.resource == "org:acme"`,
		Grant:     config.Grant{Permissions: map[string]string{"contents": "read"}},
	}}})
	d, err := e.Evaluate(input(caller("acme/app", "acme"), "org:acme"), scope(map[string]string{"contents": "read"}))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed {
		t.Fatalf("org-kind resource must match condition: %+v", d)
	}
}

func TestRuntimeEvaluationErrorIsSkipped(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("broken-at-runtime", `request.resource == "repo:acme/app" && 1 / 0 == 0`, map[string]string{"contents": "read"}),
		grantPolicy("allow", `request.resource == "repo:acme/app"`, map[string]string{"contents": "read"}),
	}})
	d, err := e.Evaluate(input(caller("acme/app", "acme"), "repo:acme/app"), scope(map[string]string{"contents": "read"}))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed || !reflect.DeepEqual(d.MatchedPolicies, []string{"allow"}) ||
		!reflect.DeepEqual(d.SkippedPolicies, []string{"broken-at-runtime"}) {
		t.Fatalf("runtime error must be skipped: %+v", d)
	}
}

func TestUnknownCELFieldsFailPolicyCompilation(t *testing.T) {
	for _, condition := range []string{
		`caller.not_a_claim == "x"`,
		`request.not_a_field == "x"`,
		`request.permissions.contents == "read"`,
		`action.owner == "acme"`,
		`caller_advisory.actor == "x"`,
	} {
		_, err := newEngine(&config.Config{
			Policies: []config.Policy{{Name: "invalid", Condition: condition + ` && request.resource == "repo:acme/app"`}},
		})
		if err == nil {
			t.Fatalf("condition %q must fail compilation", condition)
		}
	}
}

func TestCostLimitTripsAndIsSkipped(t *testing.T) {
	e := mustEngine(t, &config.Config{
		Policy: config.PolicyConfig{CostLimit: 10},
		Policies: []config.Policy{{
			Name:      "expensive",
			Condition: `request.resource == "repo:acme/app" && [1,2,3,4,5,6,7,8,9,10].all(x, [1,2,3,4,5,6,7,8,9,10].all(y, x + y > 0))`,
			Grant:     config.Grant{Permissions: map[string]string{"contents": "read"}},
		}},
	})
	d, err := e.Evaluate(input(caller("acme/app", "acme"), "repo:acme/app"), scope(map[string]string{"contents": "read"}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed || !reflect.DeepEqual(d.SkippedPolicies, []string{"expensive"}) {
		t.Fatalf("cost-limit trip must skip policy: %+v", d)
	}
}

func TestOversizedRepositoriesRejectedBeforeEvaluation(t *testing.T) {
	e := mustEngine(t, &config.Config{
		Policy: config.PolicyConfig{MaxRepositories: 2},
		Policies: []config.Policy{{
			Name: "any", Condition: `request.resource == "repo:a/1"`,
			Grant: config.Grant{Permissions: map[string]string{"contents": "read"}},
		}},
	})
	_, err := e.Evaluate(input(caller("acme/app", "acme"), "repo:a/1", "repo:a/2", "repo:a/3"), scope(map[string]string{"contents": "read"}))
	if err == nil {
		t.Fatal("oversized repositories list must be rejected, not truncated")
	}
}

func TestCompileErrorNamesPolicy(t *testing.T) {
	_, err := newEngine(&config.Config{
		Policies: []config.Policy{{Name: "broken", Condition: "this is not CEL (("}},
	})
	if err == nil {
		t.Fatal("expected compile error")
	}
}

// productionPolicies mirrors a production config: the own repository gets
// write access, its "-gitops" sibling read access.
func productionPolicies() []config.Policy {
	return []config.Policy{
		grantPolicy("self-repo-rw", `request.resource == "repo:" + caller.repository`,
			map[string]string{"contents": "write", "actions": "read"}),
		grantPolicy("gitops-sibling", `request.resource == "repo:" + caller.repository + "-gitops"`,
			map[string]string{"contents": "read"}),
	}
}

func TestPerResourceGrantEqualsSingleResourceGrant(t *testing.T) {
	tests := []struct {
		name      string
		policies  []config.Policy
		resources []string
		required  map[string]string
	}{
		{"production", productionPolicies(), []string{"repo:acme/app", "repo:acme/app-gitops"}, map[string]string{"contents": "read"}},
		{"production write", productionPolicies(), []string{"repo:acme/app", "repo:acme/app-gitops"}, map[string]string{"contents": "write"}},
		{"base and elevated", []config.Policy{
			grantPolicy("base", `request.resource in ["repo:acme/app", "repo:acme/lib"]`, map[string]string{"contents": "read"}),
			grantPolicy("elevated", `request.resource == "repo:acme/app"`, map[string]string{"contents": "write", "issues": "write"}),
		}, []string{"repo:acme/app", "repo:acme/lib", "repo:acme/other"}, map[string]string{"contents": "write"}},
		{"alias", []config.Policy{
			grantPolicy("equals", `request.resources == ["repo:acme/app"]`, map[string]string{"contents": "write"}),
			grantPolicy("in", `"repo:acme/lib" in request.resources`, map[string]string{"contents": "read"}),
		}, []string{"repo:acme/app", "repo:acme/lib", "repo:acme/victim"}, map[string]string{"contents": "read"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := mustEngine(t, &config.Config{Policies: tt.policies})
			all := evaluate(t, e, tt.required, tt.resources...)
			for _, r := range tt.resources {
				single := evaluate(t, e, tt.required, r)
				if !reflect.DeepEqual(all.Grants[r], single.Grants[r]) {
					t.Errorf("%s: grant %+v differs from single-resource grant %+v", r, all.Grants[r], single.Grants[r])
				}
				if all.Allowed && !single.Allowed {
					t.Errorf("%s: allowed in the full request but denied alone", r)
				}
			}
		})
	}
}

func TestGrantsDoNotMergeAcrossResources(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("a", `request.resource == "repo:acme/r1"`, map[string]string{"contents": "write"}),
		grantPolicy("b", `request.resource == "repo:acme/r2"`, map[string]string{"issues": "write"}),
	}})
	d := evaluate(t, e, map[string]string{"contents": "write", "issues": "write"}, "repo:acme/r1", "repo:acme/r2")
	if d.Allowed || !reflect.DeepEqual(d.UncoveredResources, []string{"repo:acme/r1", "repo:acme/r2"}) {
		t.Fatalf("grants must not merge across resources: %+v", d)
	}
}

func TestPartialLevelCoverageDenied(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("x-write", `request.resource == "repo:acme/x"`, map[string]string{"contents": "write"}),
		grantPolicy("y-read", `request.resource == "repo:acme/y"`, map[string]string{"contents": "read"}),
	}})
	d := evaluate(t, e, map[string]string{"contents": "write"}, "repo:acme/x", "repo:acme/y")
	if d.Allowed || !reflect.DeepEqual(d.UncoveredResources, []string{"repo:acme/y"}) {
		t.Fatalf("write must be denied with y uncovered: %+v", d)
	}
	if d := evaluate(t, e, map[string]string{"contents": "read"}, "repo:acme/x", "repo:acme/y"); !d.Allowed {
		t.Fatalf("read must be allowed: %+v", d)
	}
}

func TestAliasCannotSmuggleSecondRepo(t *testing.T) {
	for _, condition := range []string{
		`request.resources == ["repo:acme/app"]`,
		`"repo:acme/app" in request.resources`,
	} {
		e := mustEngine(t, &config.Config{Policies: []config.Policy{
			grantPolicy("mine", condition, map[string]string{"contents": "write"}),
		}})
		d := evaluate(t, e, map[string]string{"contents": "write"}, "repo:acme/app", "repo:acme/victim")
		if d.Allowed || !reflect.DeepEqual(d.UncoveredResources, []string{"repo:acme/victim"}) {
			t.Fatalf("%s: second repo must not be authorized: %+v", condition, d)
		}
	}
}

func TestSizeGuardDoesNotOverGrant(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("size-guard", `size(request.resources) == 2 && request.resource == "repo:acme/victim" || request.resource == "repo:acme/app"`,
			map[string]string{"contents": "write"}),
	}})
	required := map[string]string{"contents": "write"}
	if d := evaluate(t, e, required, "repo:acme/app", "repo:acme/victim"); d.Allowed {
		t.Fatalf("size guard must not authorize the second repo: %+v", d)
	}
	if d := evaluate(t, e, required, "repo:acme/victim"); d.Allowed {
		t.Fatalf("victim alone must be denied: %+v", d)
	}
}

func TestResourceWithoutMatchDeniedEvenWithEmptyScope(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("app", `request.resource == "repo:acme/app"`, map[string]string{"contents": "read"}),
	}})
	d := evaluate(t, e, map[string]string{}, "repo:acme/app", "repo:acme/other")
	if d.Allowed || !reflect.DeepEqual(d.UncoveredResources, []string{"repo:acme/other"}) {
		t.Fatalf("resource without a matching policy must be uncovered: %+v", d)
	}
}

func TestEmptyResourcesDenied(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("any", `request.resource == "repo:acme/app"`, map[string]string{"contents": "read"}),
	}})
	if d := evaluate(t, e, map[string]string{"contents": "read"}); d.Allowed {
		t.Fatalf("empty resource list must be denied: %+v", d)
	}
}

func TestDecisionIndependentOfResourceOrderAndDuplicates(t *testing.T) {
	policies := []config.Policy{
		grantPolicy("app", `request.resource == "repo:acme/app"`, map[string]string{"contents": "write"}),
		grantPolicy("all-read", `request.resource in ["repo:acme/app", "repo:acme/lib"]`, map[string]string{"contents": "read"}),
		grantPolicy("broken", `request.resource == "repo:acme/lib" && 1 / 0 == 0`, map[string]string{"issues": "write"}),
	}
	required := map[string]string{"contents": "write"}
	want := evaluate(t, mustEngine(t, &config.Config{Policies: policies}), required, "repo:acme/app", "repo:acme/lib")
	reversed := mustEngine(t, &config.Config{Policies: []config.Policy{policies[2], policies[1], policies[0]}})
	for _, resources := range [][]string{
		{"repo:acme/lib", "repo:acme/app"},
		{"repo:acme/app", "repo:acme/lib", "repo:acme/app", "repo:acme/lib"},
	} {
		if got := evaluate(t, reversed, required, resources...); !reflect.DeepEqual(got, want) {
			t.Fatalf("resources=%v: got %+v, want %+v", resources, got, want)
		}
	}
}

func TestRuntimeErrorForOneResourceDeniesOnlyThatResource(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("divide", `request.resource in ["repo:acme/app", "repo:acme/bad", "repo:acme/lib"] && `+
			`1 / (request.resource == "repo:acme/bad" ? 0 : 1) == 1`, map[string]string{"contents": "read"}),
	}})
	d := evaluate(t, e, map[string]string{"contents": "read"}, "repo:acme/app", "repo:acme/bad", "repo:acme/lib")
	if d.Allowed || !reflect.DeepEqual(d.UncoveredResources, []string{"repo:acme/bad"}) ||
		!reflect.DeepEqual(d.MatchedPolicies, []string{"divide"}) || !reflect.DeepEqual(d.SkippedPolicies, []string{"divide"}) {
		t.Fatalf("runtime error must only deny the failing resource: %+v", d)
	}
	for _, r := range []string{"repo:acme/app", "repo:acme/lib"} {
		if !reflect.DeepEqual(d.Grants[r].Permissions, map[string]string{"contents": "read"}) {
			t.Fatalf("%s: grant %+v, want contents:read", r, d.Grants[r])
		}
	}
}

func TestCapCountsFullList(t *testing.T) {
	e := mustEngine(t, &config.Config{
		Policy:   config.PolicyConfig{MaxRepositories: 2},
		Policies: []config.Policy{grantPolicy("any", `request.resource == "repo:acme/app"`, map[string]string{"contents": "read"})},
	})
	_, err := e.Evaluate(input(caller("acme/app", "acme"), "repo:acme/app", "repo:acme/app", "repo:acme/app"),
		scope(map[string]string{"contents": "read"}))
	if err == nil {
		t.Fatal("cap must count the full list, including duplicates")
	}
}

func TestPolicyGrantMapNotMutated(t *testing.T) {
	read := map[string]string{"contents": "read"}
	write := map[string]string{"contents": "write", "issues": "read"}
	e := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("read", `request.resource in ["repo:acme/app", "repo:acme/lib"]`, read),
		grantPolicy("write", `request.resource == "repo:acme/app"`, write),
	}})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			d, err := e.Evaluate(input(caller("acme/app", "acme"), "repo:acme/app", "repo:acme/lib"),
				scope(map[string]string{"contents": "read"}))
			if err != nil {
				t.Error(err)
				return
			}
			for _, g := range d.Grants {
				g.Permissions["administration"] = "write"
			}
		})
	}
	wg.Wait()
	if !maps.Equal(read, map[string]string{"contents": "read"}) ||
		!maps.Equal(write, map[string]string{"contents": "write", "issues": "read"}) {
		t.Fatalf("policy grant maps were mutated: read=%v write=%v", read, write)
	}
}

func TestAliasAndSingularAgree(t *testing.T) {
	singular := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("app", `request.resource == "repo:" + caller.repository`, map[string]string{"contents": "write"}),
	}})
	alias := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("app", `"repo:" + caller.repository in request.resources`, map[string]string{"contents": "write"}),
	}})
	for _, resources := range [][]string{
		{"repo:acme/app"},
		{"repo:acme/other"},
		{"repo:acme/app", "repo:acme/other"},
	} {
		a := evaluate(t, singular, map[string]string{"contents": "write"}, resources...)
		b := evaluate(t, alias, map[string]string{"contents": "write"}, resources...)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("resources=%v: singular %+v, alias %+v", resources, a, b)
		}
	}
}

func TestCompileWarnings(t *testing.T) {
	tests := []struct {
		condition string
		want      []string
	}{
		{`request.resource == "repo:acme/app"`, nil},
		{`request . resource == "repo:acme/app"`, nil},
		{`request.resource == "repo:acme/a" || request.resource == "repo:acme/b"`, nil},
		{`(request.resource == "repo:acme/a" || request.resource == "repo:acme/b") && caller.repository_owner == "acme"`, nil},
		{`(caller.repository == "acme/a" || caller.repository == "acme/b") && request.resource == "repo:acme/app"`, nil},
		{`"repo:acme/app" in request.resources`, []string{policy.WarnDeprecatedResources}},
		{`size(request.resources) == 1 && request.resource == "repo:acme/app"`,
			[]string{policy.WarnDeprecatedResources, policy.WarnResourcesShape}},
		{`request.resources.size() == 1 && request.resource == "repo:acme/app"`,
			[]string{policy.WarnDeprecatedResources, policy.WarnResourcesShape}},
		{`request.resources[0] == "repo:acme/app" && request.resource == "repo:acme/app"`,
			[]string{policy.WarnDeprecatedResources, policy.WarnResourcesShape}},
	}
	for _, tt := range tests {
		got, err := policy.CompileWarnings(pinnedGitHub, tt.condition)
		if err != nil {
			t.Fatalf("%s: %v", tt.condition, err)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: warnings = %q, want %q", tt.condition, got, tt.want)
		}
	}
}

func TestProductionStyleConfig(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: productionPolicies()})
	resources := []string{"repo:acme/app", "repo:acme/app-gitops"}
	if d := evaluate(t, e, map[string]string{"contents": "read"}, resources...); !d.Allowed {
		t.Fatalf("contents:read on both repos must be allowed: %+v", d)
	}
	for _, required := range []map[string]string{{"contents": "write"}, {"actions": "write"}} {
		if d := evaluate(t, e, required, resources...); d.Allowed {
			t.Fatalf("%v on both repos must be denied: %+v", required, d)
		}
	}
}

// TestCELMissingClaimSemantics pins the CEL behaviour the startup checks rely
// on: has() turns an absent claim into true, a plain read of an absent claim
// is an error, and a leading-dot caller under a shadowing comprehension keeps
// its dot in the checked AST.
func TestCELMissingClaimSemantics(t *testing.T) {
	env, err := policy.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]any{policy.VarCaller: map[string]string{}, policy.VarRequest: policy.Request{}}
	for condition, wantErr := range map[string]bool{
		`!has(caller.x) || false`: false,
		`caller.x != "a"`:         true,
	} {
		ast, iss := env.Compile(condition)
		if iss.Err() != nil {
			t.Fatal(iss.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := prg.Eval(vars)
		if wantErr != (err != nil) || (!wantErr && out.Value() != true) {
			t.Errorf("%s: out=%v err=%v", condition, out, err)
		}
	}

	ast, iss := env.Compile(`[0].exists(caller, .caller.x == "a")`)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	idents := celast.MatchDescendants(celast.NavigateAST(ast.NativeRep()), func(e celast.NavigableExpr) bool {
		return e.Kind() == celast.IdentKind && e.AsIdent() == ".caller"
	})
	if len(idents) != 1 {
		t.Fatalf("shadowed .caller not kept in the checked AST")
	}
}

func TestPoliciesBoundToIssuer(t *testing.T) {
	a := config.OIDCIssuer{Name: "a", Claims: []string{"sub"}, Require: map[string][]string{"tenant": {"1"}}}
	b := a
	b.Name = "b"
	e := mustEngine(t, &config.Config{
		OIDC: config.OIDCConfig{Issuers: []config.OIDCIssuer{a, b}},
		Policies: []config.Policy{{
			Name: "a-only", Issuer: "a", Condition: `caller.sub == "x" && request.resource == "repo:acme/app"`,
			Grant: config.Grant{Permissions: map[string]string{"contents": "read"}},
		}},
	})
	for issuer, want := range map[string]bool{"a": true, "b": false, "unknown": false} {
		d, err := e.Evaluate(policy.Input{
			Issuer: issuer, Caller: map[string]string{"sub": "x"},
			Request: policy.Request{Resources: []string{"repo:acme/app"}},
		}, scope(map[string]string{"contents": "read"}))
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed != want || (len(d.MatchedPolicies) > 0) != want {
			t.Errorf("issuer %s: %+v", issuer, d)
		}
	}
}

func TestMissingClaimSkipsPolicy(t *testing.T) {
	for _, condition := range []string{
		`caller.sub != "a" && request.resource == "repo:acme/app"`,
		`caller["sub"] == "a" && request.resource == "repo:acme/app"`,
	} {
		e := mustEngine(t, &config.Config{
			OIDC: config.OIDCConfig{Issuers: []config.OIDCIssuer{gitlab}},
			Policies: []config.Policy{{
				Name: "p", Issuer: gitlab.Name, Condition: condition,
				Grant: config.Grant{Permissions: map[string]string{"contents": "read"}},
			}},
		})
		d, err := e.Evaluate(policy.Input{
			Issuer: gitlab.Name, Caller: map[string]string{"project_path": "acme/app"},
			Request: policy.Request{Resources: []string{"repo:acme/app"}},
		}, scope(map[string]string{"contents": "read"}))
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed || !reflect.DeepEqual(d.SkippedPolicies, []string{"p"}) {
			t.Errorf("%s: missing claim must skip the policy: %+v", condition, d)
		}
	}
}

func TestNonIdentityClaimDoesNotPinCaller(t *testing.T) {
	const ref = `caller.ref == "refs/heads/main" && request.resource == "repo:acme/app"`
	_, err := newEngine(&config.Config{
		OIDC:     config.OIDCConfig{Issuers: []config.OIDCIssuer{openGitHub}},
		Policies: []config.Policy{grantPolicy("main", ref, map[string]string{"contents": "read"})},
	})
	if err == nil {
		t.Fatal("a ref comparison alone must not satisfy the caller check without require")
	}

	e := mustEngine(t, &config.Config{
		OIDC: config.OIDCConfig{Issuers: []config.OIDCIssuer{openGitHub}},
		Policies: []config.Policy{grantPolicy("main", `caller.repository == "acme/app" && `+ref,
			map[string]string{"contents": "read"})},
	})
	for repository, want := range map[string]bool{"acme/app": true, "evil/app": false} {
		c := map[string]string{"repository": repository, "ref": "refs/heads/main"}
		d, err := e.Evaluate(input(c, "repo:acme/app"), scope(map[string]string{"contents": "read"}))
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed != want {
			t.Errorf("%s: allowed = %t, want %t", repository, d.Allowed, want)
		}
	}
}

func TestAbsentPresetClaimSkipsPolicy(t *testing.T) {
	e := mustEngine(t, &config.Config{Policies: []config.Policy{
		grantPolicy("prod", `caller.environment == "prod" && request.resource == "repo:acme/app"`, map[string]string{"contents": "read"}),
	}})
	required := scope(map[string]string{"contents": "read"})
	d, err := e.Evaluate(input(caller("acme/app", "acme"), "repo:acme/app"), required)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed || len(d.MatchedPolicies) != 0 || !reflect.DeepEqual(d.SkippedPolicies, []string{"prod"}) {
		t.Fatalf("policy reading an absent claim must be skipped: %+v", d)
	}
	c := caller("acme/app", "acme")
	c["environment"] = "prod"
	if d, err := e.Evaluate(input(c, "repo:acme/app"), required); err != nil || !d.Allowed {
		t.Fatalf("policy must match with the claim present: %+v %v", d, err)
	}
}

func TestConditionRules(t *testing.T) {
	const app = ` && request.resource == "repo:acme/app"`
	tests := []struct {
		issuer    config.OIDCIssuer
		condition string
		ok        bool
	}{
		// Accepted forms.
		{pinnedGitHub, `request.resource == "repo:acme/app"`, true},
		{pinnedGitHub, `.request.resource == "repo:acme/app"`, true},
		{openGitHub, `request.resource == "repo:" + caller.repository`, true},
		{openGitHub, `request.resource == "repo:" + caller["repository"]`, true},
		{openGitHub, `request.resource == "repo:" + caller.repository + "-gitops"`, true},
		{openGitHub, `request.resource == "repo:" + caller.repository_owner + "/tools"`, true},
		{openGitHub, `request.resource == "org:" + caller.repository_owner`, true},
		{openGitHub, `request.resource in ["repo:" + caller.repository, "repo:" + caller.repository + "-gitops"]`, true},
		{openGitHub, `"repo:" + caller.repository in request.resources`, true},
		{openGitHub, `caller.repository == "acme/app" && request.resource == "repo:acme/shared"`, true},
		{openGitHub, `caller.repository_owner == "acme" && request.resource in ["repo:acme/shared", "repo:" + caller.repository]`, true},
		{openGitHub, `caller.repository_owner == "acme"` + app, true},
		{openGitHub, `caller["repository_owner"] == "acme"` + app, true},
		{openGitHub, `.caller.repository_owner == "acme"` + app, true},
		{openGitHub, `caller.repository_owner in ["acme", "other"]` + app, true},
		{gitlab, `request.resource in ["repo:acme/a", "repo:acme/b"]`, true},
		{gitlab, `"repo:acme/app" == request.resource && caller.project_path == "acme/app"`, true},
		{gitlab, `(request.resource == "repo:acme/a" && caller.sub == "x") || request.resource == "repo:acme/b"`, true},
		{openGitHub, `caller.workflow_ref == "acme/app/.github/workflows/deploy.yml@refs/heads/main"` + app, true},
		{openGitHub, `caller.repository_owner == "acme" && caller.job_workflow_ref == "acme/shared/.github/workflows/deploy.yml@refs/heads/main"` + app, true},
		{openGitHub, `caller.job_workflow_ref == "acme/shared/.github/workflows/deploy.yml@refs/heads/main"` + app, false},
		{openGitHub, `caller.enterprise_id in ["7"]` + app, true},
		{openGitHub, `caller.repository == "acme/app" && caller.ref == "refs/heads/main"` + app, true},
		{openGitHub, `caller.repository == "acme/app" && caller.runner_environment == "github-hosted"` + app, true},
		{openGitHub, `caller.repository == "acme/app" && caller.event_name == "push"` + app, true},
		{openGitHub, `caller.repository == "acme/app" && caller.repository_visibility == "private"` + app, true},
		{openGitHub, `caller.repository == "acme/app" && caller.environment == "prod"` + app, true},
		{openGitHub, `caller.repository == "acme/app" && caller.sub == "repo:acme/app:environment:prod"` + app, true},
		{openGitHub, `caller.repository == "acme/app" && (caller.repository_id == "1" || caller.ref == "refs/heads/main")` + app, true},
		{pinnedGitHub, `caller.ref == "refs/heads/main"` + app, true},
		{pinnedGitHub, `caller.runner_environment == "github-hosted"` + app, true},
		{pinnedGitHub, `caller.event_name == "push"` + app, true},
		{pinnedGitHub, `caller.repository_visibility == "private"` + app, true},
		{pinnedGitHub, `caller.environment == "prod"` + app, true},
		{pinnedGitHub, `caller.sub == "repo:acme/app:environment:prod"` + app, true},
		{pinnedGitHub, `caller.ref_protected == "true" && caller.ref_type == "branch" && caller.sha == "abc"` + app, true},
		{pinnedGitHub, `caller.ref == caller.repository` + app, true},

		// Unconstrained resource.
		{pinnedGitHub, `true`, false},
		{pinnedGitHub, `caller.repository == "acme/app"`, false},
		{pinnedGitHub, `request.resource != "repo:acme/app"`, false},
		{pinnedGitHub, `!(request.resource == "repo:acme/app")`, false},
		{pinnedGitHub, `(request.resource == "repo:acme/app") == false`, false},
		{pinnedGitHub, `request.resource == request.resource`, false},
		{pinnedGitHub, `size(request.resource) == 13`, false},
		{pinnedGitHub, `has(request.resource) == true`, false},
		{pinnedGitHub, `request.resources.exists(r, r == "repo:acme/app")`, false},
		{pinnedGitHub, `request.resource == "repo:acme/app" || caller.repository == "acme/admin"`, false},
		{pinnedGitHub, "caller.repository == \"acme/app\" // request.resource\n", false},
		{pinnedGitHub, `"request.resource" != "" && caller.repository == "acme/app"`, false},

		// Unconstrained caller without require.
		{openGitHub, `request.resource == "repo:acme/app"`, false},
		{openGitHub, `caller.repository != "acme/app"` + app, false},
		{openGitHub, `caller.repository == caller.repository_owner` + app, false},
		{openGitHub, `caller.repository == "acme/app"` + app + ` || request.resource == "repo:acme/lib"`, false},
		{openGitHub, `caller.repository == caller.workflow_ref` + app, false},
		{openGitHub, `caller.ref == caller.repository` + app, false},

		// Only non-identity claims compared, without require.
		{openGitHub, `caller.ref == "refs/heads/main"` + app, false},
		{openGitHub, `caller.ref in ["refs/heads/main"]` + app, false},
		{openGitHub, `caller.runner_environment == "github-hosted"` + app, false},
		{openGitHub, `caller.event_name == "push"` + app, false},
		{openGitHub, `caller.repository_visibility == "private"` + app, false},
		{openGitHub, `caller.environment == "prod"` + app, false},
		{openGitHub, `caller.environment_node_id == "EN_1"` + app, false},
		{openGitHub, `caller.sub == "repo:acme/app:environment:prod"` + app, false},
		{openGitHub, `caller.issuer_scope == "enterprise"` + app, false},
		{openGitHub, `caller.ref_protected == "true" && caller.sha == "abc"` + app, false},
		{openGitHub, `(caller.repository == "acme/app" || caller.ref == "refs/heads/main")` + app, false},
		{openGitHub, `caller.repository == "acme/app"` + app + ` || caller.ref == "refs/heads/main"` + app, false},
		{openGeneric, `caller.project_path == "acme/app"` + app, false},

		// Resource not anchored to the caller, without require.
		{openGitHub, `request.resource in ["repo:acme/shared", "repo:" + caller.repository]`, false},
		{openGitHub, `request.resource == (caller.repository_owner == "acme" ? "repo:acme/shared" : "repo:acme/shared")`, false},
		{openGitHub, `request.resource == "repo:acme/shared" + (caller.repository == "" ? "" : "")`, false},
		{openGitHub, `request.resource in ["repo:acme/shared"] + [caller.repository]`, false},
		{openGitHub, `request.resource in {"repo:acme/shared": true, caller.repository: true}`, false},
		{openGitHub, `request.resource == "repo:acme/" + caller.repository_owner`, false},
		{openGitHub, `request.resource == "repo:" + caller.repository_owner`, false},
		{openGitHub, `request.resource == "repo:" + caller.repository_owner + "tools"`, false},
		{openGitHub, `request.resource == "org:" + caller.repository_owner + "x"`, false},
		{openGitHub, `request.resource == "repo:" + caller.job_workflow_ref`, false},
		{openGitHub, `request.resource == "repo:" + (caller.repository + "-gitops")`, false},

		// String functions and ordering comparisons.
		{gitlab, `caller.sub.startsWith("a")` + app, false},
		{gitlab, `caller.sub.endsWith("a")` + app, false},
		{gitlab, `caller.sub.contains("a")` + app, false},
		{gitlab, `caller.sub.matches("^a")` + app, false},
		{gitlab, `matches(caller.sub, "^a")` + app, false},
		{pinnedGitHub, `request.resource.startsWith("repo:acme/")` + app, false},
		{gitlab, `caller.sub > "a"` + app, false},
		{pinnedGitHub, `request.resource >= "repo:acme/"` + app, false},

		// Non-literal resource for a non-preset issuer.
		{gitlab, `request.resource == "repo:" + caller.project_path`, false},
		{gitlab, `request.resource in ["repo:" + caller.project_path]`, false},
		{gitlab, `request.resource == "repo:acme/" + "app"`, false},
		{gitlab, `"repo:acme/app" in request.resources`, false},
		{gitlab, `[request].exists(r, r.resource != "")` + app, false},

		// Caller access other than a declared claim.
		{gitlab, `has(caller.sub)` + app, false},
		{gitlab, `(!has(caller.sub) || false)` + app, false},
		{gitlab, `!has(caller.sub) || false`, false},
		{gitlab, `caller.?sub == "x"` + app, false},
		{gitlab, `caller[?"sub"] == "x"` + app, false},
		{gitlab, `"sub" in caller` + app, false},
		{gitlab, `size(caller) == 1` + app, false},
		{gitlab, `caller.exists(k, k == "sub")` + app, false},
		{gitlab, `caller.all(k, caller[k] == "x")` + app, false},
		{gitlab, `caller[request.resource] == "x"` + app, false},
		{gitlab, `caller["s" + "ub"] == "x"` + app, false},
		{gitlab, `caller == {"sub": "x"}` + app, false},
		{gitlab, `dyn(caller).sub == "x"` + app, false},
		{gitlab, `caller.undeclared == "x"` + app, false},
		{gitlab, `.caller.undeclared == "x"` + app, false},
		{gitlab, `caller["undeclared"] == "x"` + app, false},
		{gitlab, `caller.repository == "acme/app"` + app, false},
		{pinnedGitHub, `caller.actor == "octocat"` + app, false},
		{pinnedGitHub, `caller.actor_id == "1"` + app, false},
		{pinnedGitHub, `caller.head_ref == "main"` + app, false},
		{pinnedGitHub, `caller.base_ref == "main"` + app, false},
		{pinnedGitHub, `caller.workflow == "CI"` + app, false},
		{pinnedGitHub, `caller.run_id == "1"` + app, false},

		// Shadowed policy variables.
		{gitlab, `[0].exists(caller, .caller.sub == "x")` + app, false},
		{pinnedGitHub, `[1].exists(request, request == 1)` + app, false},
		{pinnedGitHub, `[1].map(caller, caller)[0] == 1` + app, false},
	}
	for _, tt := range tests {
		_, err := policy.CompileWarnings(tt.issuer, tt.condition)
		if tt.ok != (err == nil) {
			t.Errorf("issuer %s preset=%t: %s: err = %v", tt.issuer.Name, tt.issuer.IsPreset(), tt.condition, err)
		}
	}
}

func TestCallerAnchoredResourceDeniesOtherOwners(t *testing.T) {
	for _, condition := range []string{
		`request.resource in ["repo:" + caller.repository, "repo:" + caller.repository + "-gitops"]`,
		`request.resource == "repo:" + caller.repository_owner + "/shared"`,
		`request.resource == "org:" + caller.repository_owner`,
		`caller.repository_owner == "acme" && request.resource in ["repo:acme/shared", "repo:" + caller.repository]`,
	} {
		e := mustEngine(t, &config.Config{
			OIDC:     config.OIDCConfig{Issuers: []config.OIDCIssuer{openGitHub}},
			Policies: []config.Policy{grantPolicy("p", condition, map[string]string{"contents": "read"})},
		})
		for _, r := range []string{"repo:acme/shared", "org:acme"} {
			d, err := e.Evaluate(input(caller("evil/x", "evil"), r), scope(map[string]string{"contents": "read"}))
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed {
				t.Errorf("%s: caller evil/x must be denied %s: %+v", condition, r, d)
			}
		}
	}
}
