package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/target"
)

// Round 26: the running-binary identity is captured BEFORE the scenario. If the
// exercise restarts/re-execs the service into different bytes (or an unconfined
// context), binding the verdict to the pre-capture would attest a process that
// did not do the work. exercise() must re-capture afterward and fail closed.
func TestExerciseFailsOnMidRunIdentityChange(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{
		responses: map[string]string{
			"stat -c '%s %i'": "0 4242",
			"stat -c '%i'":    "4242",
		},
		seq: map[string][]string{
			// Same PID query, DIFFERENT binary before vs after the scenario.
			"systemctl show -p MainPID": {
				"LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
				"LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/evil\nEXESHA:" + strings.Repeat("cd", 32),
			},
		},
	}
	_, _, _, err := exercise(f, tgt, "widget_t")
	if err == nil || !strings.Contains(err.Error(), "changed identity") {
		t.Fatalf("mid-run identity change must fail closed, got err=%v", err)
	}
}

// A same-identity restart (new pid, same binary/label/digest) is benign and
// must NOT trip the identity check.
func TestExerciseToleratesSameIdentityRestart(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	same := "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32)
	f := &fakeRunner{responses: map[string]string{
		"stat -c '%s %i'":           "0 4242",
		"stat -c '%i'":              "4242",
		"systemctl show -p MainPID": same,
	}}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err != nil {
		t.Fatalf("same-identity restart must not fail: %v", err)
	}
}

// Round 26: %pre must fail closed if the roots inventory exists but cannot be
// stashed (else the upgrade silently retains stale labels); and upgrade
// rollback must re-apply the OLD module's labels on every old root.
func TestSpecUpgradeReconcileFailClosedAndRollback(t *testing.T) {
	spec := GenerateSpec(testTarget().Profile(), "20260101000000")
	if !strings.Contains(spec, "refusing a non-atomic upgrade") {
		t.Error("pre-install scriptlet must fail closed when the roots stash cannot be written")
	}
	// The rollback branch must iterate the old roots (re-apply old labels).
	if !strings.Contains(spec, ".oldroots") || !strings.Contains(spec, "_oldroot") {
		t.Errorf("rollback must restore every old root:\n%s", spec)
	}
}

// Round 27: a fresh RPM install must REFUSE if a module with our name already
// exists (foreign — manual, base policy, or another package); loading ours would
// shadow it and rollback would remove it.
func TestSpecFreshInstallRefusesPreexistingModule(t *testing.T) {
	spec := GenerateSpec(testTarget().Profile(), "20260101000000")
	if !strings.Contains(spec, "semodule -l") || !strings.Contains(spec, "fresh install") {
		t.Errorf("%%post must refuse a pre-existing module on fresh install:\n%s", spec)
	}
}
