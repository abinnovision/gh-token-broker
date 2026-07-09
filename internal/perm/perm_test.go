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
