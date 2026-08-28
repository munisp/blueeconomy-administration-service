package pbac

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// policyDir returns the shipped fleet policy directory; the matrix tests
// evaluate the production policy, not a fixture copy.
func policyDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "policies")
	if _, err := os.Stat(filepath.Join(dir, "admin.rego")); err != nil {
		t.Fatalf("shipped policy directory missing: %v", err)
	}
	return dir
}

func loadEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := LoadPolicyDir(policyDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func onboardingInput(roles []string, tenant, resourceTenant, action string) Input {
	return Input{
		Roles:     roles,
		TenantID:  tenant,
		Resource:  Resource{Kind: "onboarding_request", ID: "req-1", TenantID: resourceTenant},
		Action:    action,
		Clearance: "CONFIDENTIAL",
	}
}

func TestApproverMatrix(t *testing.T) {
	engine := loadEngine(t)
	ctx := context.Background()
	cases := []struct {
		name  string
		input Input
		allow bool
	}{
		{"approver same tenant may decide", onboardingInput([]string{"nimasa-officer"}, "nimasa", "nimasa", "decide"), true},
		{"platform admin same tenant may provision", onboardingInput([]string{"platform-admin"}, "nimasa", "nimasa", "provision"), true},
		{"platform admin same tenant may activate", onboardingInput([]string{"platform-admin"}, "nimasa", "nimasa", "activate"), true},
		{"approver cross-tenant decide denied", onboardingInput([]string{"nimasa-officer"}, "nimasa", "nwa", "decide"), false},
		{"platform admin cross-tenant activate denied", onboardingInput([]string{"platform-admin"}, "nimasa", "nwa", "activate"), false},
		{"operator role cannot decide", onboardingInput([]string{"nwa-officer"}, "nwa", "nwa", "decide"), false},
		{"operator role cannot provision", onboardingInput([]string{"niwa-officer"}, "niwa", "niwa", "provision"), false},
		{"read-only auditor cannot decide", onboardingInput([]string{"independent-auditor"}, "nimasa", "nimasa", "decide"), false},
		{"read-only observer cannot activate", onboardingInput([]string{"cbn-observer"}, "nimasa", "nimasa", "activate"), false},
		{"empty tenant denied", onboardingInput([]string{"nimasa-officer"}, "", "nimasa", "decide"), false},
		{"unknown action denied", onboardingInput([]string{"platform-admin"}, "nimasa", "nimasa", "delete"), false},
		{"unknown resource kind denied", func() Input {
			input := onboardingInput([]string{"platform-admin"}, "nimasa", "nimasa", "decide")
			input.Resource.Kind = "ledger"
			return input
		}(), false},
	}
	for _, testCase := range cases {
		allowed, err := engine.Allow(ctx, testCase.input)
		// Validation errors are also denials (fail-closed).
		if err != nil && testCase.allow {
			t.Fatalf("%s: %v", testCase.name, err)
		}
		if err != nil {
			allowed = false
		}
		if allowed != testCase.allow {
			t.Fatalf("%s: allow=%v, want %v", testCase.name, allowed, testCase.allow)
		}
	}
}

func documentInput(roles []string, clearance, classification string) Input {
	return Input{
		Roles:          roles,
		Clearance:      clearance,
		TenantID:       "nimasa",
		Resource:       Resource{Kind: "document", ID: "doc-1", TenantID: "nimasa"},
		Action:         "read",
		Classification: classification,
	}
}

func TestClassifierGatedDocumentAccess(t *testing.T) {
	engine := loadEngine(t)
	ctx := context.Background()
	cases := []struct {
		name  string
		input Input
		allow bool
	}{
		{"secret reader opens fiduciary document", documentInput([]string{"independent-auditor"}, "SECRET", "FIDUCIARY_SEGREGATED"), true},
		{"confidential reader opens internal document", documentInput([]string{"nimasa-officer"}, "CONFIDENTIAL", "INTERNAL"), true},
		{"confidential reader denied fiduciary document", documentInput([]string{"nimasa-officer"}, "CONFIDENTIAL", "FIDUCIARY_SEGREGATED"), false},
		{"unclassified reader denied restricted document", documentInput([]string{"nimasa-officer"}, "UNCLASSIFIED", "RESTRICTED"), false},
		{"unlabelled reader denied confidential document", documentInput([]string{"nimasa-officer"}, "", "CONFIDENTIAL"), false},
		{"unknown clearance label denied", documentInput([]string{"nimasa-officer"}, "COSMIC", "INTERNAL"), false},
		{"unknown classification denied", documentInput([]string{"nimasa-officer"}, "SECRET", "EYES-ONLY"), false},
		{"unrecognized role denied", documentInput([]string{"superuser"}, "SECRET", "PUBLIC"), false},
		{"write action denied for document", func() Input {
			input := documentInput([]string{"platform-admin"}, "SECRET", "PUBLIC")
			input.Action = "write"
			return input
		}(), false},
	}
	for _, testCase := range cases {
		allowed, err := engine.Allow(ctx, testCase.input)
		if err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}
		if allowed != testCase.allow {
			t.Fatalf("%s: allow=%v, want %v", testCase.name, allowed, testCase.allow)
		}
	}
}

func TestLoadPolicyDirFailsClosed(t *testing.T) {
	if _, err := LoadPolicyDir(""); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, err := LoadPolicyDir(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("absent directory accepted")
	}
	empty := t.TempDir()
	if _, err := LoadPolicyDir(empty); err == nil {
		t.Fatal("directory without .rego modules accepted")
	}
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "broken.rego"), []byte("package broken\n\nthis is not rego"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyDir(broken); err == nil {
		t.Fatal("broken rego module accepted")
	}
	oversized := t.TempDir()
	if err := os.WriteFile(filepath.Join(oversized, "big.rego"), make([]byte, maxPolicyFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyDir(oversized); err == nil {
		t.Fatal("oversized module accepted")
	}
	if _, err := LoadPolicyDir(filepath.Join(policyDir(t), "admin.rego")); err == nil {
		t.Fatal("regular file accepted as policy directory")
	}
}

func TestAllowFailsClosed(t *testing.T) {
	engine := loadEngine(t)
	var nilEngine *Engine
	if allowed, err := nilEngine.Allow(context.Background(), onboardingInput([]string{"platform-admin"}, "a", "a", "decide")); err == nil || allowed {
		t.Fatal("nil engine allowed access")
	}
	if _, err := engine.Allow(context.Background(), Input{}); err == nil {
		t.Fatal("empty input accepted")
	}
	input := onboardingInput([]string{"platform-admin"}, "a", "a", "decide")
	input.Roles = nil
	if _, err := engine.Allow(context.Background(), input); err == nil {
		t.Fatal("role-less input accepted")
	}
}

func TestSortedRolesDeterministic(t *testing.T) {
	first := SortedRoles(map[string]struct{}{"b": {}, "a": {}, "c": {}})
	second := SortedRoles(map[string]struct{}{"c": {}, "a": {}, "b": {}})
	if len(first) != 3 || first[0] != "a" || first[2] != "c" {
		t.Fatalf("unsorted: %v", first)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatal("non-deterministic ordering")
		}
	}
}
