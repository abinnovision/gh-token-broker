package resource

import (
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name  string
			input string
			want  Resource
		}{
			{
				name:  "backward compat owner/repo",
				input: "acme/app",
				want:  Resource{Kind: KindRepo, Owner: "acme", Name: "app", Raw: "repo:acme/app"},
			},
			{
				name:  "prefixed repo",
				input: "repo:acme/app",
				want:  Resource{Kind: KindRepo, Owner: "acme", Name: "app", Raw: "repo:acme/app"},
			},
			{
				name:  "org",
				input: "org:acme",
				want:  Resource{Kind: KindOrg, Owner: "acme", Name: "", Raw: "org:acme"},
			},
			{
				name:  "enterprise",
				input: "enterprise:abi-group-gmbh",
				want:  Resource{Kind: KindEnterprise, Owner: "abi-group-gmbh", Name: "", Raw: "enterprise:abi-group-gmbh"},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				got, err := Parse(tc.input)
				if err != nil {
					t.Fatalf("Parse(%q) returned unexpected error: %v", tc.input, err)
				}

				if got != tc.want {
					t.Fatalf("Parse(%q) = %+v, want %+v", tc.input, got, tc.want)
				}
			})
		}
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()

		invalid := []string{
			"",
			"repo:",
			"repo:acme",
			"org:acme/something",
			"unknown:foo",
			"noslash",
		}

		for _, input := range invalid {
			t.Run(input, func(t *testing.T) {
				t.Parallel()

				if _, err := Parse(input); err == nil {
					t.Fatalf("Parse(%q) expected error, got nil", input)
				}
			})
		}
	})
}

func TestParseAll(t *testing.T) {
	t.Parallel()

	t.Run("multiple repos same owner", func(t *testing.T) {
		t.Parallel()

		resources, err := ParseAll([]string{"repo:acme/app", "acme/lib"})
		if err != nil {
			t.Fatalf("ParseAll returned unexpected error: %v", err)
		}

		if len(resources) != 2 {
			t.Fatalf("ParseAll returned %d resources, want 2", len(resources))
		}
	})

	t.Run("mixed kinds rejected", func(t *testing.T) {
		t.Parallel()

		if _, err := ParseAll([]string{"repo:acme/app", "org:acme"}); err == nil {
			t.Fatal("ParseAll expected error for mixed kinds, got nil")
		}
	})

	t.Run("mixed owners rejected", func(t *testing.T) {
		t.Parallel()

		if _, err := ParseAll([]string{"repo:acme/app", "repo:other/app"}); err == nil {
			t.Fatal("ParseAll expected error for mixed owners, got nil")
		}
	})

	t.Run("multiple orgs rejected", func(t *testing.T) {
		t.Parallel()

		if _, err := ParseAll([]string{"org:acme", "org:other"}); err == nil {
			t.Fatal("ParseAll expected error for multiple orgs, got nil")
		}
	})

	t.Run("single org", func(t *testing.T) {
		t.Parallel()

		resources, err := ParseAll([]string{"org:acme"})
		if err != nil {
			t.Fatalf("ParseAll returned unexpected error: %v", err)
		}

		if len(resources) != 1 {
			t.Fatalf("ParseAll returned %d resources, want 1", len(resources))
		}
	})

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()

		if _, err := ParseAll(nil); err == nil {
			t.Fatal("ParseAll expected error for empty input, got nil")
		}
	})
}

func TestHelperFunctions(t *testing.T) {
	t.Parallel()

	t.Run("repo resources", func(t *testing.T) {
		t.Parallel()

		resources, err := ParseAll([]string{"repo:acme/app", "repo:acme/lib"})
		if err != nil {
			t.Fatalf("ParseAll returned unexpected error: %v", err)
		}

		if got, want := Owner(resources), "acme"; got != want {
			t.Errorf("Owner() = %q, want %q", got, want)
		}

		gotFull := RepoFullNames(resources)
		wantFull := []string{"acme/app", "acme/lib"}
		if !equalSlices(gotFull, wantFull) {
			t.Errorf("RepoFullNames() = %v, want %v", gotFull, wantFull)
		}

		gotShort := RepoShortNames(resources)
		wantShort := []string{"app", "lib"}
		if !equalSlices(gotShort, wantShort) {
			t.Errorf("RepoShortNames() = %v, want %v", gotShort, wantShort)
		}

		gotRaw := RawStrings(resources)
		wantRaw := []string{"repo:acme/app", "repo:acme/lib"}
		if !equalSlices(gotRaw, wantRaw) {
			t.Errorf("RawStrings() = %v, want %v", gotRaw, wantRaw)
		}
	})

	t.Run("org resources", func(t *testing.T) {
		t.Parallel()

		resources, err := ParseAll([]string{"org:acme"})
		if err != nil {
			t.Fatalf("ParseAll returned unexpected error: %v", err)
		}

		if got, want := Owner(resources), "acme"; got != want {
			t.Errorf("Owner() = %q, want %q", got, want)
		}

		if got := RepoFullNames(resources); got != nil {
			t.Errorf("RepoFullNames() = %v, want nil", got)
		}

		if got := RepoShortNames(resources); got != nil {
			t.Errorf("RepoShortNames() = %v, want nil", got)
		}

		gotRaw := RawStrings(resources)
		wantRaw := []string{"org:acme"}
		if !equalSlices(gotRaw, wantRaw) {
			t.Errorf("RawStrings() = %v, want %v", gotRaw, wantRaw)
		}
	})
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
