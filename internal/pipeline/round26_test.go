package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
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

// Round 28: stale-port reconciliation must FAIL CLOSED if `semanage port -l`
// cannot enumerate — inlining it in $(...) would yield an empty loop and let
// obsolete <app>_port_t mappings (undeclared bind privilege) survive.
func TestSpecPortReconcileFailsClosedOnEnumError(t *testing.T) {
	p := testTarget().Profile()
	p.Ports = []profile.Port{{Proto: "tcp", Port: 8443}}
	spec := GenerateSpec(p, "20260101000000")
	if !strings.Contains(spec, "_portlist=") {
		t.Errorf("reconcile must capture the listing before iterating:\n%s", spec)
	}
	if !strings.Contains(spec, "'semanage port -l' failed") {
		t.Errorf("reconcile must abort on an enumeration failure:\n%s", spec)
	}
}

// Round 29: kernel audit LOSS during the exercise means the denial slice may be
// incomplete — a zero-denial result would be a false pass. exercise() must fail
// closed when the lost counter climbs.
func TestExerciseFailsClosedOnAuditLoss(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{
		responses: map[string]string{
			"stat -c '%s %i'":           "0 4242",
			"stat -c '%i'":              "4242",
			"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
		},
		seq: map[string][]string{
			// lost climbs 0 -> 7 across the window; backlog 0 so the drain breaks.
			"auditctl -s": {"enabled 1 lost 0 backlog 0", "enabled 1 lost 7 backlog 0"},
		},
	}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err == nil || !strings.Contains(err.Error(), "lost") {
		t.Fatalf("audit record loss must fail closed, got %v", err)
	}
}

// Round 29: a pre-existing SELinux type must be detected via seinfo (not only a
// process ALLOW rule), and a query error must fail closed (not look "absent").
func TestRunDetectsPreexistingTypeAndFailsClosedOnQueryError(t *testing.T) {
	// Pre-existing type: seinfo resolves widget_t.
	f := passingRunner()
	f.responses["seinfo -t widget_t"] = "Types: 1\n   widget_t\n"
	if res := Run(f, testTarget(), Options{MaxRounds: 2}); !strings.Contains(res.FailureReason, "already exists") {
		t.Errorf("a defined type must be detected as a conflict, got %q", res.FailureReason)
	}
	// Both query tools fail: cannot determine existence → fail closed.
	f2 := passingRunner()
	f2.failOn = []string{"seinfo -t widget_t", "sesearch -A -s widget_t"}
	if res := Run(f2, testTarget(), Options{MaxRounds: 2}); !strings.Contains(res.FailureReason, "cannot query SELinux type") {
		t.Errorf("a query failure must fail closed, got %q", res.FailureReason)
	}
}

// Round 29: an app-owned path hard-linked to a shared inode (link count > 1)
// must NOT be labeled — restorecon would relabel the shared inode and affect
// every other link. The entrypoint is refused, so its digest is never bound.
func TestRunRefusesHardLinkedEntrypoint(t *testing.T) {
	f := passingRunner()
	f.responses["stat -c %h"] = "2" // the entrypoint inode has 2 links → shared
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if _, bound := res.EntrypointDigests["/opt/widget/bin/widgetd"]; bound {
		t.Error("a hard-linked (shared-inode) entrypoint must not be labeled or bound")
	}
}
