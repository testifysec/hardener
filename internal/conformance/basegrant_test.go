package conformance

import (
	"testing"

	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
)

// The base TE template pre-grants shell exec, /etc read, cert access, etc.
// Those produce no AVC, so they never enter FinalRules — yet they are real
// privilege a second-party supplier must declare. ExtractObserved must
// surface them, or the conformance contract has a hole (review finding).
func TestBaseGrantsAppearInObserved(t *testing.T) {
	p := &profile.Profile{Name: "widget"}
	obs := ExtractObserved(p, nil)
	set := map[string]bool{}
	for _, f := range obs.BaseGrants {
		set[f] = true
	}
	for _, want := range []string{"corecmd_exec_shell", "files_read_etc_files", "auth_use_nsswitch"} {
		if !set[want] {
			t.Errorf("base grant %q missing from observed: %v", want, obs.BaseGrants)
		}
	}
	// The single-source-of-truth invariant: every generator base interface is observed.
	if len(obs.BaseGrants) != len(policy.BaseInterfaces) {
		t.Errorf("observed base grants (%d) must equal generator base interfaces (%d)",
			len(obs.BaseGrants), len(policy.BaseInterfaces))
	}
}

// A second-party supplier that declares nothing about base access fails
// conformance for it — the grant is undeclared behavior.
func TestUndeclaredBaseGrantIsAViolation(t *testing.T) {
	obs := Observed{BaseGrants: []string{"corecmd_exec_shell", "files_read_etc_files"}}
	decl := &profile.Declaration{BaseGrants: []string{"files_read_etc_files"}} // shell exec NOT declared
	rep := Compare(decl, obs)
	found := false
	for _, f := range rep.Undeclared {
		if f.Kind == "base-grant" && f.Item == "corecmd_exec_shell" {
			found = true
		}
	}
	if !found {
		t.Errorf("undeclared base grant must be a violation: %+v", rep.Undeclared)
	}
}

// A supplier that declares its base access passes.
func TestDeclaredBaseGrantsPass(t *testing.T) {
	all := append([]string(nil), policy.BaseInterfaces...)
	obs := Observed{BaseGrants: all}
	decl := &profile.Declaration{BaseGrants: all}
	if rep := Compare(decl, obs); len(rep.Undeclared) != 0 {
		t.Errorf("fully declared base grants must pass: %+v", rep.Undeclared)
	}
}
