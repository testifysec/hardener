package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/target"
)

// buildRPM must compile the packaged .pp FRESH from the verified policy text
// (res.FinalTE/FinalFC) in a dedicated pkg dir, never copying the staged
// /tmp/hardener/<app>/<app>.pp — a root-privileged exercise could have swapped
// that staged file after enforcement, packaging unverified policy bytes while
// the loaded module stayed clean. (review finding — round 55)
func TestBuildRPMPackagesFreshlyCompiledVerifiedPolicy(t *testing.T) {
	f := passingRunner()
	p := &profile.Profile{Name: "widget", Executables: []string{"/opt/widget/bin/widgetd"}}
	verifiedTE := "policy_module(widget, 1.0.0)\ntype widget_t;\n"
	verifiedFC := "/opt/widget/bin/widgetd -- gen_context(system_u:object_r:widget_exec_t,s0)\n"
	if _, err := buildRPM(f, p, "20260101000000", verifiedTE, verifiedFC); err != nil {
		t.Fatalf("buildRPM: %v", err)
	}

	compiledFresh := false
	copiedStagedPP := false
	for _, c := range f.calls {
		if strings.Contains(c, "cd /tmp/hardener/widget/pkg") &&
			strings.Contains(c, "make -f /usr/share/selinux/devel/Makefile widget.pp") {
			compiledFresh = true
		}
		// The OLD behavior copied the staged (non-pkg) .pp directly.
		if strings.Contains(c, "cp /tmp/hardener/widget/widget.pp ") {
			copiedStagedPP = true
		}
	}
	if !compiledFresh {
		t.Error("buildRPM must recompile the .pp from verified text in the pkg dir")
	}
	if copiedStagedPP {
		t.Error("buildRPM must NOT copy the swappable staged /tmp/hardener/widget/widget.pp")
	}
}

// The exercise write barrier must emit an ordered audit SENTINEL (auditctl -m)
// and wait for it — a size-stabilization heuristic can race a late append. When
// the sentinel is FOUND, it satisfies the barrier even if the log size never
// stabilizes (the sentinel proves auditd flushed everything before it), so the
// racy size-stable fallback is not needed. (review finding — round 56)
func TestExerciseEmitsAuditSentinelAndSkipsFallbackWhenFound(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{
		responses: map[string]string{
			"stat -c '%s %i'":           "0 4242",
			"stat -c '%i'":              "4242",
			"stat -c '%s'":              "0",
			"auditctl -s":               "enabled 1 lost 0 backlog 0",
			"is-active widget.service":  "inactive",
			"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
			// The sentinel is present in the log → primary barrier satisfied.
			"grep -Fc": "1",
		},
	}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err != nil {
		t.Fatalf("a found sentinel must satisfy the write barrier: %v", err)
	}
	// The sentinel must actually have been emitted.
	emitted := false
	for _, c := range f.calls {
		if strings.Contains(c, "auditctl -m") && strings.Contains(c, "hardener-barrier-") {
			emitted = true
		}
	}
	if !emitted {
		t.Error("exercise must emit an ordered audit sentinel (auditctl -m hardener-barrier-...)")
	}
}

// A same-NAME module content replacement (a broader policy swapped in under the
// app's own module name) leaves the module NAME set unchanged, so moduleNameSet
// misses it. recheck also compares the loaded module's CONTENT digest against
// what was last installed; a drift means the enforced policy no longer matches
// FinalTE/the RPM and must fail closed. (review finding — round 57)
func TestRecheckFailsOnSameNameModuleContentSwap(t *testing.T) {
	f := passingRunner()
	good := strings.Repeat("a", 64) + "  -"
	bad := strings.Repeat("b", 64) + "  -"
	// Two installs (observe + final) capture 'good'; the next content probe (a
	// recheck) sees 'bad' → same-name content swap detected.
	f.seq = map[string][]string{
		"active/modules": {good, good, bad},
	}
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" || !strings.Contains(res.FailureReason, "module content changed") {
		t.Fatalf("a same-name module content swap must fail closed, got %q", res.FailureReason)
	}
}

// moduleContentDigest must FAIL CLOSED when the module files cannot be collected
// (empty input must NOT hash to a passing constant). An uncollectable digest at
// install time fails the run rather than establishing a meaningless baseline.
// (review finding — round 58)
func TestRunFailsClosedWhenModuleDigestUncollectable(t *testing.T) {
	f := passingRunner()
	f.responses["active/modules"] = "NO_MODULE_FILES" // find matched nothing
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" || !strings.Contains(res.FailureReason, "module-content-baseline") {
		t.Fatalf("an uncollectable module digest must fail closed, got %q", res.FailureReason)
	}
}
