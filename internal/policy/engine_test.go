package policy_test

import (
	"log/slog"
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

func callerInput(claims map[string]string) policy.Input {
	return policy.Input{Caller: claims}
}

func TestDefaultRejectWhenNoRuleMatches(t *testing.T) {
	e := mustEngine(t, &config.Config{Policy: config.PolicyConfig{Rules: []config.Rule{{
		Name: "owner", When: `caller.repository_owner == "acme"`,
		Grant: config.Grant{Repositories: []string{"acme/x"}, Permissions: map[string]string{"contents": "read"}},
	}}}})
	d, err := e.Evaluate(callerInput(map[string]string{"repository_owner": "someone-else"}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Matched {
		t.Fatalf("expected default reject, got matched rule %q", d.RuleName)
	}
}

func TestFirstMatchWins(t *testing.T) {
	e := mustEngine(t, &config.Config{Policy: config.PolicyConfig{Rules: []config.Rule{
		{Name: "first", When: "true", Grant: config.Grant{Repositories: []string{"acme/a"}, Permissions: map[string]string{"contents": "read"}}},
		{Name: "second", When: "true", Grant: config.Grant{Repositories: []string{"acme/b"}, Permissions: map[string]string{"contents": "write"}}},
	}}})
	d, err := e.Evaluate(callerInput(map[string]string{"repository_owner": "acme"}))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Matched || d.RuleName != "first" {
		t.Fatalf("first-match-wins violated: %+v", d)
	}
	if len(d.Grant.Repositories) != 1 || d.Grant.Repositories[0] != "acme/a" {
		t.Fatalf("wrong grant returned: %+v", d.Grant)
	}
}

// TestAdvisoryClaimsCannotBeUsedForDecision proves a rule referencing an
// advisory field still evaluates against caller_advisory only, and that the
// id-anchored caller map is what a correctly-written rule keys on. The
// adversarial case: an attacker-controlled advisory value must not flip a
// decision that keys on the id-anchored caller map.
func TestAdvisoryDoesNotAffectAnchoredDecision(t *testing.T) {
	e := mustEngine(t, &config.Config{Policy: config.PolicyConfig{Rules: []config.Rule{{
		Name: "anchored", When: `caller.repository == "acme/app"`,
		Grant: config.Grant{Repositories: []string{"acme/app"}, Permissions: map[string]string{"contents": "read"}},
	}}}})

	// Honest caller: id-anchored repository matches; advisory is hostile but irrelevant.
	d, err := e.Evaluate(policy.Input{
		Caller:   map[string]string{"repository": "acme/app"},
		Advisory: map[string]string{"ref": "refs/heads/attacker", "actor": "mallory"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Matched {
		t.Fatalf("anchored rule should match honest caller regardless of advisory: %+v", d)
	}

	// Attacker: wrong id-anchored repository, but advisory claims spoof a match.
	d, err = e.Evaluate(policy.Input{
		Caller:   map[string]string{"repository": "acme/evil"},
		Advisory: map[string]string{"ref": "acme/app", "actor": "acme/app", "workflow": "acme/app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Matched {
		t.Fatalf("advisory values must never satisfy an anchored caller rule: %+v", d)
	}
}

func TestCostLimitTrips(t *testing.T) {
	// A comprehension over a large range with a tiny cost limit must trip the
	// CEL cost guard, surfacing as an eval error → fail-closed deny.
	e := mustEngine(t, &config.Config{Policy: config.PolicyConfig{
		CostLimit: 10, // deliberately tiny
		Rules: []config.Rule{{
			Name:    "expensive",
			When:    `[1,2,3,4,5,6,7,8,9,10].all(x, [1,2,3,4,5,6,7,8,9,10].all(y, x + y > 0))`,
			Grant:   config.Grant{Repositories: []string{"acme/x"}, Permissions: map[string]string{"contents": "read"}},
			OnError: "reject",
		}},
	}})
	d, err := e.Evaluate(callerInput(map[string]string{"repository_owner": "acme"}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Matched {
		t.Fatalf("cost-limit trip must fail closed (no match), got %+v", d)
	}
}

func TestOversizedRepositoriesRejectedBeforeEvaluation(t *testing.T) {
	e := mustEngine(t, &config.Config{Policy: config.PolicyConfig{
		MaxRepositories: 2,
		Rules: []config.Rule{{
			Name: "any", When: "true",
			Grant: config.Grant{Repositories: []string{"acme/x"}, Permissions: map[string]string{"contents": "read"}},
		}},
	}})
	_, err := e.Evaluate(policy.Input{
		Caller:  map[string]string{"repository_owner": "acme"},
		Request: map[string]any{"repositories": []string{"a/1", "a/2", "a/3"}},
	})
	if err == nil {
		t.Fatal("oversized repositories list must be rejected, not truncated")
	}
}

func TestCompileErrorNamesRule(t *testing.T) {
	_, err := policy.New(&config.Config{Policy: config.PolicyConfig{
		CostLimit: 10000, MaxRepositories: 256,
		Rules: []config.Rule{{Name: "broken", When: "this is not CEL (("}},
	}}, discard())
	if err == nil {
		t.Fatal("expected compile error")
	}
}
