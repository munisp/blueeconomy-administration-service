// Package pbac is the embedded-OPA policy-based authorization gate for the
// administration service. Policies live in a mounted directory of Rego
// modules (policies/admin.rego in this repository); the loader and the
// evaluator are both fail-closed: an unreadable directory, an empty policy
// set, a compile error or an evaluation error denies access.
package pbac

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/rego"
)

// allowQuery is the binding policy decision point. The policy document
// defines data.blueeconomy.admin.allow (default false).
const allowQuery = "data.blueeconomy.admin.allow"

// maxPolicyFileBytes bounds one Rego module; policies are small reviewed
// documents, never bulk data.
const maxPolicyFileBytes = 1 << 20

// Resource identifies the protected object.
type Resource struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}

// Input is the authorization context evaluated against the policy.
type Input struct {
	Roles          []string `json:"roles"`
	Clearance      string   `json:"clearance"`
	TenantID       string   `json:"tenant_id"`
	Resource       Resource `json:"resource"`
	Action         string   `json:"action"`
	Classification string   `json:"classification"`
}

// Engine evaluates the prepared allow query.
type Engine struct {
	prepared rego.PreparedEvalQuery
}

// LoadPolicyDir compiles every .rego module in dir and prepares the allow
// query. It fails closed: a missing/unreadable directory, no .rego modules,
// an unreadable/oversized module, or a compile error is an error and no
// engine is returned.
func LoadPolicyDir(dir string) (*Engine, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("policy directory path is required")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat policy directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("policy path %q is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy directory: %w", err)
	}
	var modules []func(*rego.Rego)
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		stat, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat policy module %s: %w", entry.Name(), err)
		}
		if !stat.Mode().IsRegular() || stat.Size() == 0 || stat.Size() > maxPolicyFileBytes {
			return nil, fmt.Errorf("policy module %s is not a regular file between 1 and %d bytes", entry.Name(), maxPolicyFileBytes)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy module %s: %w", entry.Name(), err)
		}
		modules = append(modules, rego.Module(entry.Name(), string(content)))
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("policy directory %q contains no .rego modules", dir)
	}
	return LoadModules(modules...)
}

// LoadModules compiles the given module options into an engine.
func LoadModules(modules ...func(*rego.Rego)) (*Engine, error) {
	if len(modules) == 0 {
		return nil, errors.New("at least one policy module is required")
	}
	options := append([]func(*rego.Rego){rego.Query(allowQuery)}, modules...)
	prepared, err := rego.New(options...).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("compile policy modules: %w", err)
	}
	return &Engine{prepared: prepared}, nil
}

// Allow evaluates the policy. Any evaluation failure or a non-boolean/true
// decision denies access (deny-by-default).
func (e *Engine) Allow(ctx context.Context, input Input) (bool, error) {
	if e == nil {
		return false, errors.New("policy engine is required")
	}
	if err := input.Validate(); err != nil {
		return false, err
	}
	results, err := e.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, fmt.Errorf("evaluate authorization policy: %w", err)
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, nil
	}
	allow, ok := results[0].Expressions[0].Value.(bool)
	return ok && allow, nil
}

// Validate enforces canonical, bounded input fields; malformed input denies.
func (input Input) Validate() error {
	if len(input.Roles) == 0 {
		return errors.New("authorization input carries no roles")
	}
	for _, role := range input.Roles {
		if err := canonicalText("role", role, 128); err != nil {
			return err
		}
	}
	if err := canonicalText("tenant_id", input.TenantID, 256); err != nil {
		return err
	}
	if err := canonicalText("resource.kind", input.Resource.Kind, 128); err != nil {
		return err
	}
	if err := canonicalText("resource.id", input.Resource.ID, 256); err != nil {
		return err
	}
	if err := canonicalText("resource.tenant_id", input.Resource.TenantID, 256); err != nil {
		return err
	}
	if err := canonicalText("action", input.Action, 64); err != nil {
		return err
	}
	// Clearance and classification may be empty (unlabelled callers); the
	// policy treats unknown labels as deny.
	if input.Clearance != "" {
		if err := canonicalText("clearance", input.Clearance, 64); err != nil {
			return err
		}
	}
	if input.Classification != "" {
		if err := canonicalText("classification", input.Classification, 64); err != nil {
			return err
		}
	}
	return nil
}

func canonicalText(field, value string, limit int) error {
	if value == "" || len(value) > limit || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be canonical non-empty text of at most %d bytes", field, limit)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s must not contain control characters", field)
		}
	}
	return nil
}

// SortedRoles returns a deterministic role list for evaluation.
func SortedRoles(held map[string]struct{}) []string {
	roles := make([]string, 0, len(held))
	for role := range held {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}
