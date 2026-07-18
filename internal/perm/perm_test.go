package perm_test

import (
	"reflect"
	"testing"

	"github.com/abinnovision/gh-token-broker/internal/perm"
)

func TestIntersectTakesMinimumLevel(t *testing.T) {
	got := perm.Intersect(
		map[string]string{"contents": "write"},
		map[string]string{"contents": "read"},
	)
	want := map[string]string{"contents": "read"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestIntersectMinAcrossThreeInputs(t *testing.T) {
	got := perm.Intersect(
		map[string]string{"contents": "admin"},
		map[string]string{"contents": "write"},
		map[string]string{"contents": "read"},
	)
	if got["contents"] != "read" {
		t.Fatalf("got %v, want contents=read", got)
	}
}

func TestIntersectDropsKeyAbsentFromAnyInput(t *testing.T) {
	got := perm.Intersect(
		map[string]string{"contents": "read", "issues": "write"},
		map[string]string{"contents": "read"}, // issues absent here
	)
	if _, present := got["issues"]; present {
		t.Fatalf("issues must be dropped when absent from an input: %v", got)
	}
	if got["contents"] != "read" {
		t.Fatalf("contents should survive: %v", got)
	}
}

func TestIntersectDropsUnknownPermissionKey(t *testing.T) {
	// "not_a_real_permission" is not in the canonical table and must be
	// dropped even if it appears in every input (INV-10, fail closed).
	got := perm.Intersect(
		map[string]string{"not_a_real_permission": "write", "contents": "read"},
		map[string]string{"not_a_real_permission": "write", "contents": "read"},
	)
	if _, present := got["not_a_real_permission"]; present {
		t.Fatalf("unknown key must never pass through: %v", got)
	}
	if got["contents"] != "read" {
		t.Fatalf("contents should survive: %v", got)
	}
}

func TestIntersectDropsInvalidLevel(t *testing.T) {
	got := perm.Intersect(
		map[string]string{"contents": "superuser"},
		map[string]string{"contents": "read"},
	)
	if len(got) != 0 {
		t.Fatalf("invalid level must be dropped, got %v", got)
	}
}

func TestIntersectEmptyInputsYieldsEmpty(t *testing.T) {
	if got := perm.Intersect(); len(got) != 0 {
		t.Fatalf("no inputs must yield empty, got %v", got)
	}
	if got := perm.Intersect(map[string]string{"contents": "read"}, map[string]string{}); len(got) != 0 {
		t.Fatalf("intersection with empty map must be empty, got %v", got)
	}
}

func TestSatisfiesRequiresAtLeastTheRequiredLevel(t *testing.T) {
	required := map[string]string{"actions": "write"}
	if perm.Satisfies(required, map[string]string{"actions": "read"}) {
		t.Fatal("granted level below required must not satisfy")
	}
	if !perm.Satisfies(required, map[string]string{"actions": "write"}) {
		t.Fatal("granted level equal to required must satisfy")
	}
	if !perm.Satisfies(required, map[string]string{"actions": "admin"}) {
		t.Fatal("granted level above required must satisfy")
	}
}

func TestSatisfiesFailsWhenRequiredKeyMissing(t *testing.T) {
	required := map[string]string{"actions": "write"}
	if perm.Satisfies(required, map[string]string{"contents": "admin"}) {
		t.Fatal("granting an unrelated permission must not satisfy a different required key")
	}
	if perm.Satisfies(required, nil) {
		t.Fatal("nil granted must not satisfy a non-empty requirement")
	}
}

func TestSatisfiesTrivialWhenNothingRequired(t *testing.T) {
	if !perm.Satisfies(nil, nil) {
		t.Fatal("no requirement must always be satisfied")
	}
	if !perm.Satisfies(map[string]string{}, map[string]string{"contents": "read"}) {
		t.Fatal("no requirement must be satisfied regardless of what's granted")
	}
}

func TestValidKeyAndLevel(t *testing.T) {
	if !perm.ValidKey("contents") || perm.ValidKey("bogus") {
		t.Fatal("ValidKey wrong")
	}
	if !perm.ValidLevel("admin") || perm.ValidLevel("root") {
		t.Fatal("ValidLevel wrong")
	}
}

func TestLevelOrd(t *testing.T) {
	cases := map[string]int{
		"read":    1,
		"write":   2,
		"admin":   3,
		"unknown": 0,
	}
	for level, want := range cases {
		if got := perm.LevelOrd(level); got != want {
			t.Fatalf("LevelOrd(%q) = %d, want %d", level, got, want)
		}
	}
}

func TestGaps(t *testing.T) {
	tests := []struct {
		name     string
		required map[string]string
		granted  map[string]string
		check    func(t *testing.T, got map[string]string)
	}{
		{
			name:     "fully satisfied",
			required: map[string]string{"contents": "read"},
			granted:  map[string]string{"contents": "write"},
			check: func(t *testing.T, got map[string]string) {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
			},
		},
		{
			name:     "missing key",
			required: map[string]string{"contents": "read", "issues": "write"},
			granted:  map[string]string{"contents": "read"},
			check: func(t *testing.T, got map[string]string) {
				if _, ok := got["issues"]; !ok {
					t.Fatalf("expected gap for issues, got %v", got)
				}
				if _, ok := got["contents"]; ok {
					t.Fatalf("contents should not have a gap, got %v", got)
				}
			},
		},
		{
			name:     "insufficient level",
			required: map[string]string{"contents": "write"},
			granted:  map[string]string{"contents": "read"},
			check: func(t *testing.T, got map[string]string) {
				want := "need write, have read"
				if got["contents"] != want {
					t.Fatalf("got %q, want %q", got["contents"], want)
				}
			},
		},
		{
			name:     "mixed",
			required: map[string]string{"contents": "write", "issues": "read"},
			granted:  map[string]string{"contents": "read", "issues": "write"},
			check: func(t *testing.T, got map[string]string) {
				if len(got) != 1 {
					t.Fatalf("got %v, want exactly one gap", got)
				}
				if _, ok := got["contents"]; !ok {
					t.Fatalf("expected gap for contents, got %v", got)
				}
			},
		},
		{
			name:     "empty required",
			required: map[string]string{},
			granted:  map[string]string{"contents": "read"},
			check: func(t *testing.T, got map[string]string) {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := perm.Gaps(tt.required, tt.granted)
			tt.check(t, got)
		})
	}
}

func TestCatalogIsNotEmpty(t *testing.T) {
	if len(perm.Catalog) < 40 {
		t.Fatalf("Catalog has %d entries, expected at least 40", len(perm.Catalog))
	}
}

func TestValidKeyLevel(t *testing.T) {
	tests := []struct {
		key, level string
		want       bool
	}{
		{"contents", "read", true},
		{"contents", "write", true},
		{"contents", "admin", false},
		{"workflows", "write", true},
		{"workflows", "read", false},
		{"bogus", "read", false},
		{"contents", "superuser", false},
	}
	for _, tt := range tests {
		t.Run(tt.key+":"+tt.level, func(t *testing.T) {
			if got := perm.ValidKeyLevel(tt.key, tt.level); got != tt.want {
				t.Fatalf("ValidKeyLevel(%q, %q) = %v, want %v", tt.key, tt.level, got, tt.want)
			}
		})
	}
}

func TestCatalogLevelsAreValid(t *testing.T) {
	for key, levels := range perm.Catalog {
		for _, l := range levels {
			if !perm.ValidLevel(l) {
				t.Errorf("Catalog[%q] contains invalid level %q", key, l)
			}
		}
	}
}
