package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
)

// Round 13: rule identity includes the SOURCE domain. A rule for one domain
// must not suppress or absorb the same target/class/perm observed for a
// DIFFERENT source (an entrypoint denial is attributed to init_t; the planned
// multi-domain split emits several sources). Omitting source dropped or merged
// cross-domain rules.
func TestMergeAndNormalizeKeepDistinctSources(t *testing.T) {
	acc := []policy.AllowRule{
		{Source: "app_t", Target: "etc_t", Class: "file", Perms: []string{"read"}},
	}
	// Same target/class/perm, different source domain — must be added, not
	// swallowed by the app_t rule.
	if n := mergeNewRules(&acc, []policy.AllowRule{
		{Source: "init_t", Target: "etc_t", Class: "file", Perms: []string{"read"}},
	}); n != 1 {
		t.Errorf("a rule for a different source domain must count as new, got added=%d", n)
	}
	var srcs []string
	for _, r := range acc {
		if r.Target == "etc_t" {
			srcs = append(srcs, r.Source)
		}
	}
	if len(srcs) != 2 {
		t.Errorf("both source domains must survive normalization, got %v", srcs)
	}

	// normalizeRules directly: two sources, one target/class → two rules.
	out := normalizeRules([]policy.AllowRule{
		{Source: "app_t", Target: "var_t", Class: "dir", Perms: []string{"search"}},
		{Source: "init_t", Target: "var_t", Class: "dir", Perms: []string{"search"}},
	})
	if len(out) != 2 {
		t.Errorf("rules with different sources must not merge, got %d: %+v", len(out), out)
	}
}

// Round 12, finding #1: declaring a shared interpreter directly in the manifest
// must NOT launder it into an entrypoint. The resolve loop now validates every
// executable — including unchanged (non-symlink) paths — so the interpreter
// blacklist has to win over the declared-executable tie, or a manifest naming
// /usr/bin/bash would relabel the shell into the app domain.
func TestDeclaredSharedInterpreterStillRejected(t *testing.T) {
	for _, bad := range []string{"/usr/bin/bash", "/bin/sh", "/usr/bin/python3", "/usr/bin/env"} {
		p := &profile.Profile{Name: "myapp", Executables: []string{bad}}
		if isAppOwnedExecutable(p, bad) {
			t.Errorf("declaring %s directly must not make it app-owned (interpreter blacklist must beat the declared tie)", bad)
		}
	}
	// A genuinely app-owned declared binary is still accepted.
	p := &profile.Profile{Name: "myapp", Executables: []string{"/opt/myapp/bin/myappd"}}
	if !isAppOwnedExecutable(p, "/opt/myapp/bin/myappd") {
		t.Error("a real app-owned declared entrypoint must remain app-owned")
	}
}

// Round 12, finding #2: a static-verification query that FAILS to execute must
// fail closed. Appending "; true" and discarding the error made a broken
// sesearch query (empty output, non-zero exit) indistinguishable from a clean
// "no denials" result, so a domain could be recorded as passing when
// verification never actually ran.
func TestStaticCheckFailsClosedWhenQueryErrors(t *testing.T) {
	f := &fakeRunner{
		responses: map[string]string{
			"command -v sesearch": "TOOLS_OK",                         // tooling gate
			"-s init_t":           "allow init_t bin_t:file execute;", // canary non-empty
		},
		// The shadow_t query cannot run (tool crash / bad policy). It must NOT
		// be read as "no shadow access".
		failOn: []string{"-t shadow_t"},
	}
	checks := staticChecks(f, "myapp_t")

	var shadow, etc *StaticCheck
	for i := range checks {
		switch {
		case strings.Contains(checks[i].Name, "shadow_t"):
			shadow = &checks[i]
		case strings.Contains(checks[i].Name, "etc_t"):
			etc = &checks[i]
		}
	}
	if shadow == nil || etc == nil {
		t.Fatalf("expected shadow_t and etc_t checks, got %+v", checks)
	}
	if shadow.Passed {
		t.Errorf("a sesearch query that failed to execute must fail closed, got Passed=true: %+v", *shadow)
	}
	if !strings.Contains(shadow.Detail, "fail-closed") {
		t.Errorf("failed query should be labeled fail-closed, got detail %q", shadow.Detail)
	}
	// A query that ran cleanly and matched nothing is still a genuine pass —
	// the fix must not turn every check into a failure.
	if !etc.Passed {
		t.Errorf("a clean empty query must still pass, got %+v", *etc)
	}
}

// Round 14: the permissive check requires semanage to SUCCEED, then decides
// membership in Go. A domain absent from a successful listing passes; a
// semanage that fails to run is unverifiable and must fail closed (the old
// piped `semanage | grep` read a semanage failure as "not permissive").
func TestPermissiveCheckRequiresSemanageSuccess(t *testing.T) {
	base := map[string]string{
		"command -v sesearch": "TOOLS_OK",
		"-s init_t":           "allow init_t bin_t:file execute;",
	}
	find := func(checks []StaticCheck) StaticCheck {
		for _, c := range checks {
			if strings.Contains(c.Name, "permissive") {
				return c
			}
		}
		t.Fatal("no permissive check produced")
		return StaticCheck{}
	}

	// semanage succeeds, domain NOT listed → pass.
	ok := base
	ok["semanage permissive -l"] = "unconfined_service_t\nother_daemon_t"
	if c := find(staticChecks(&fakeRunner{responses: ok}, "myapp_t")); !c.Passed {
		t.Errorf("domain absent from a successful listing must pass, got %+v", c)
	}

	// semanage succeeds, domain IS listed → fail.
	listed := map[string]string{
		"command -v sesearch":    "TOOLS_OK",
		"-s init_t":              "allow init_t bin_t:file execute;",
		"semanage permissive -l": "myapp_t\nother_daemon_t",
	}
	if c := find(staticChecks(&fakeRunner{responses: listed}, "myapp_t")); c.Passed {
		t.Errorf("a permissive domain must fail the check, got %+v", c)
	}

	// semanage FAILS to run → fail closed (not "clean").
	failing := &fakeRunner{
		responses: map[string]string{
			"command -v sesearch": "TOOLS_OK",
			"-s init_t":           "allow init_t bin_t:file execute;",
		},
		failOn: []string{"semanage permissive"},
	}
	if c := find(staticChecks(failing, "myapp_t")); c.Passed {
		t.Errorf("a semanage that cannot run must fail closed, got %+v", c)
	}
}
