package policy_test

import (
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/abinnovision/gh-token-broker/internal/config"
	"github.com/abinnovision/gh-token-broker/internal/policy"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func mustEngine(t *testing.T, cfg *config.Config) *policy.Engine {
	t.Helper()
	if cfg.Policy.CostLimit == 0 {
		cfg.Policy.CostLimit = 10000
	}
	if cfg.Policy.MaxRepositories == 0 {
		cfg.Policy.MaxRepositories = 256
	}
	e, err := policy.New(cfg, discard())
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return e
}

func caller(repository, owner string) policy.Caller {
	return policy.Caller{Repository: repository, RepositoryOwner: owner}
}

func input(c policy.Caller, resources ...string) policy.Input {
	return policy.Input{Caller: c, Request: policy.Request{Resources: resources}}
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
		Name: "owner", Condition: `caller.repository_owner == "acme"`,
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
		{Name: "contents-read", Condition: "true", Grant: config.Grant{Permissions: map[string]string{"contents": "read"}}},
		{Name: "contents-write", Condition: "true", Grant: config.Grant{Permissions: map[string]string{"contents": "write"}}},
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
		Name: "contents-read", Condition: "true",
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
		Condition: `request.resources.all(r, r == "repo:" + caller.repository)`,
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
		Condition: `request.resources.all(r, r == "org:acme")`,
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
		{Name: "broken-at-runtime", Condition: "1 / 0 == 0", Grant: config.Grant{Permissions: map[string]string{"contents": "read"}}},
		{Name: "allow", Condition: "true", Grant: config.Grant{Permissions: map[string]string{"contents": "read"}}},
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
		_, err := policy.New(&config.Config{
			Policy:   config.PolicyConfig{CostLimit: 10000, MaxRepositories: 256},
			Policies: []config.Policy{{Name: "invalid", Condition: condition}},
		}, discard())
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
			Condition: `[1,2,3,4,5,6,7,8,9,10].all(x, [1,2,3,4,5,6,7,8,9,10].all(y, x + y > 0))`,
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
			Name: "any", Condition: "true",
			Grant: config.Grant{Permissions: map[string]string{"contents": "read"}},
		}},
	})
	_, err := e.Evaluate(input(caller("acme/app", "acme"), "repo:a/1", "repo:a/2", "repo:a/3"), scope(map[string]string{"contents": "read"}))
	if err == nil {
		t.Fatal("oversized repositories list must be rejected, not truncated")
	}
}

func TestCompileErrorNamesPolicy(t *testing.T) {
	_, err := policy.New(&config.Config{
		Policy:   config.PolicyConfig{CostLimit: 10000, MaxRepositories: 256},
		Policies: []config.Policy{{Name: "broken", Condition: "this is not CEL (("}},
	}, discard())
	if err == nil {
		t.Fatal("expected compile error")
	}
}

// productionPolicies mirrors a production config: the own repository gets
// write access, its "-gitops" sibling read access.
func productionPolicies() []config.Policy {
	return []config.Policy{
		grantPolicy("self-repo-rw", `request.resources.all(r, r == "repo:" + caller.repository)`,
			map[string]string{"contents": "write", "actions": "read"}),
		grantPolicy("gitops-sibling", `request.resources.all(r, r == "repo:" + caller.repository + "-gitops")`,
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
		{"exists and in", []config.Policy{
			grantPolicy("exists", `request.resources.exists(r, r == "repo:acme/app")`, map[string]string{"contents": "write"}),
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

func TestExistsAndInCannotSmuggleSecondRepo(t *testing.T) {
	for _, condition := range []string{
		`request.resources.exists(r, r == "repo:acme/app")`,
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
		grantPolicy("size-guard", `size(request.resources) > 1 || request.resource == "repo:acme/app"`,
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
		grantPolicy("any", "true", map[string]string{"contents": "read"}),
	}})
	if d := evaluate(t, e, map[string]string{"contents": "read"}); d.Allowed {
		t.Fatalf("empty resource list must be denied: %+v", d)
	}
}

func TestDecisionIndependentOfResourceOrderAndDuplicates(t *testing.T) {
	policies := []config.Policy{
		grantPolicy("app", `request.resource == "repo:acme/app"`, map[string]string{"contents": "write"}),
		grantPolicy("all-read", "true", map[string]string{"contents": "read"}),
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
		grantPolicy("divide", `1 / (request.resource == "repo:acme/bad" ? 0 : 1) == 1`, map[string]string{"contents": "read"}),
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
		Policies: []config.Policy{grantPolicy("any", "true", map[string]string{"contents": "read"})},
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
		grantPolicy("read", "true", read),
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
		grantPolicy("app", `request.resources.all(r, r == "repo:" + caller.repository)`, map[string]string{"contents": "write"}),
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
		{`(request.resource == "repo:acme/a" || caller.repository == "acme/b") && caller.repository_owner == "acme"`,
			[]string{policy.WarnUnconstrained}},
		{`request.resources.all(r, r == "repo:acme/app")`, []string{policy.WarnDeprecatedResources}},
		{`caller.repository_owner == "acme"`, []string{policy.WarnUnconstrained}},
		{`request.resource == "repo:acme/app" || caller.repository == "acme/admin"`, []string{policy.WarnUnconstrained}},
		{"caller.repository == \"acme/app\" // request.resource\n", []string{policy.WarnUnconstrained}},
		{`"request.resource" != "" && caller.repository == "acme/app"`, []string{policy.WarnUnconstrained}},
		{`size(request.resources) == 1 && request.resource == "repo:acme/app"`,
			[]string{policy.WarnDeprecatedResources, policy.WarnResourcesShape}},
		{`request.resources.size() == 1 && request.resource == "repo:acme/app"`,
			[]string{policy.WarnDeprecatedResources, policy.WarnResourcesShape}},
		{`request.resources[0] == "repo:acme/app"`,
			[]string{policy.WarnDeprecatedResources, policy.WarnResourcesShape}},
	}
	for _, tt := range tests {
		got, err := policy.CompileWarnings(tt.condition)
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
