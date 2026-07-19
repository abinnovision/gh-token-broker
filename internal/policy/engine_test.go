package policy_test

import (
	"log/slog"
	"reflect"
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
	if !forward.Allowed || !backward.Allowed || !reflect.DeepEqual(forward.Grant, backward.Grant) {
		t.Fatalf("combined grant must be allowed and independent of policy order: forward=%+v backward=%+v", forward, backward)
	}
	if !reflect.DeepEqual(forward.Grant.Permissions, map[string]string{"contents": "write"}) {
		t.Fatalf("wrong aggregate grant: %+v", forward.Grant)
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
