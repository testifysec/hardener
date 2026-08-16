package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/target"
)

// Round 66: recheck() samples the module store only before/after the exercise, so
// a privileged exercise can load a broad allow module, run the workload clean, and
// remove it before returning — both samples pass. Every module load/unload emits a
// kernel MAC_POLICY_LOAD record, and the transient swap happens during the exercise
// (before the sentinel), so it lands in the window. exercise() must fail closed on it.
func TestExerciseFailsClosedOnTransientPolicySwap(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{
		responses: map[string]string{
			"stat -c '%s %i'":           "100 4242",
			"stat -c '%s'":              "100",
			"stat -c '%i'":              "4242",
			"auditctl -s":               "enabled 1 lost 0 backlog 0",
			"grep -Fc":                  "1",
			"is-active widget.service":  "inactive",
			"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
			// A module was loaded (and would be removed) during the exercise window.
			"tail -c": "type=MAC_POLICY_LOAD msg=audit(1700000000.123:99): auid=0 ses=1 lsm=selinux res=1",
		},
	}
	_, _, _, err := exercise(f, tgt, "widget_t")
	if err == nil || !strings.Contains(err.Error(), "policy was reloaded during the exercise") {
		t.Fatalf("a MAC_POLICY_LOAD in the window must fail closed, got %v", err)
	}
}

// Round 66: %post relabels every p.Paths root and verifies it receives the app
// type; a path with no mapping in the shipped .fc can never get that type, so the
// RPM fails to install. buildRPM must refuse to package such an inconsistent pair
// (spec derived from a path the shipped .fc omits).
func TestBuildRPMFailsClosedOnSpecFCMismatch(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths: []profile.PathAccess{
			{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"},
		},
	}
	f := &fakeRunner{responses: map[string]string{}}
	// A .fc that OMITS the /var/lib/widget mapping (a collision-trimmed fc shipped
	// with an untrimmed profile) — the exact install-breaking mismatch.
	fc := "/opt/widget/bin/widgetd\t--\tgen_context(system_u:object_r:widget_exec_t,s0)\n"
	_, err := buildRPM(f, p, "20260101000000", "(te)", fc)
	if err == nil || !strings.Contains(err.Error(), "no mapping for it") {
		t.Fatalf("buildRPM must fail closed on a spec/fc path mismatch, got %v", err)
	}
	// A consistent .fc (exactly what the profile produces) must clear the guard —
	// any later failure on the fake is fine, but not the guard's mismatch error.
	good := policy.GenerateFC(p)
	if _, err := buildRPM(f, p, "20260101000000", "(te)", good); err != nil && strings.Contains(err.Error(), "no mapping for it") {
		t.Fatalf("a consistent fc must clear the spec/fc guard, got %v", err)
	}
}
