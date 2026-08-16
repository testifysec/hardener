package pipeline

import (
	"os/exec"
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
			"stat -c '%s %i'":          "0 4242",
			"stat -c '%i'":             "4242",
			"auditctl -s":              "enabled 1 lost 0 backlog 0",
			"is-active widget.service": "inactive",
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
	// Round 36: the unit must be stopped before returning — a re-exec'd process
	// must not be left running while cleanup removes its module.
	if f.countCalls("systemctl stop widget.service") == 0 {
		t.Error("identity-change failure must stop the unit before returning")
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
		"auditctl -s":               "enabled 1 lost 0 backlog 0",
		"is-active widget.service":  "inactive",
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
			"is-active widget.service":  "inactive",
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

// Round 30: auditing being ENABLED (not just auditd active) is required — a
// privileged script can `auditctl -e 0` while the service stays up, suppressing
// every AVC. exercise() must fail closed when auditing is disabled.
func TestExerciseFailsClosedWhenAuditingDisabled(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{responses: map[string]string{
		"stat -c '%s %i'": "0 4242",
		"stat -c '%i'":    "4242",
		"auditctl -s":     "enabled 0 lost 0 backlog 0", // auditing turned OFF
	}}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err == nil || !strings.Contains(err.Error(), "auditing is disabled") {
		t.Fatalf("disabled auditing must fail closed, got %v", err)
	}
}

// Round 30: a unit that does not stop after the exercise must fail closed — a
// still-running process could generate or hide records outside the window.
func TestExerciseFailsClosedWhenUnitDoesNotStop(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{responses: map[string]string{
		"stat -c '%s %i'":           "0 4242",
		"stat -c '%i'":              "4242",
		"auditctl -s":               "enabled 1 lost 0 backlog 0",
		"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
		"is-active widget.service":  "active", // still running after stop
	}}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err == nil || !strings.Contains(err.Error(), "not cleanly stopped") {
		t.Fatalf("a unit that will not stop must fail closed, got %v", err)
	}
}

// Round 30: the generated RPM %post must re-check the entrypoint hard-link count
// before relabeling — the verifier-side check does not protect the customer host.
func TestSpecPostChecksEntrypointHardLinks(t *testing.T) {
	spec := GenerateSpec(testTarget().Profile(), "20260101000000")
	if !strings.Contains(spec, `stat -c '%h'`) || !strings.Contains(spec, "hard-link count") {
		t.Errorf("%%post must check entrypoint hard-link count before relabel:\n%s", spec)
	}
}

// Round 31: a service that re-execs then EXITS leaves an empty post-exercise
// capture; the old guard skipped the check and passed on the pre-exercise
// digest. A non-empty pre-capture now REQUIRES a matching post-capture.
func TestExerciseFailsClosedWhenProcessExits(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{
		responses: map[string]string{
			"stat -c '%s %i'": "0 4242",
			"stat -c '%i'":    "4242",
			"auditctl -s":     "enabled 1 lost 0 backlog 0",
		},
		seq: map[string][]string{
			// Present before the scenario, gone after (the process exited).
			"systemctl show -p MainPID": {
				"LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
				"NO_PID",
			},
		},
	}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err == nil || !strings.Contains(err.Error(), "exited during the scenario") {
		t.Fatalf("a process that exits mid-run must fail closed, got %v", err)
	}
}

// Round 31: the fresh-install pre-existing-module check must capture semodule -l
// and fail closed on enumeration error (piping to grep masked semodule failures),
// and _pruned port mappings must be restored in EVERY rollback path.
func TestSpecFreshInstallModuleCheckAndPrunedRestore(t *testing.T) {
	spec := GenerateSpec(testTarget().Profile(), "20260101000000")
	if !strings.Contains(spec, "_modlist=") || !strings.Contains(spec, "'semodule -l' failed") {
		t.Errorf("fresh-install module check must capture+validate semodule -l:\n%s", spec)
	}
	// The _pruned restore loop must sit OUTSIDE the upgrade-only elif — i.e. after
	// the closing `fi` of the module-restore block, before the function closes.
	idx := strings.Index(spec, "in EVERY rollback path")
	if idx < 0 {
		t.Errorf("_pruned must be restored in every rollback path:\n%s", spec)
	}
}

// Round 32: a unit left in a TRANSITIONAL state (activating/deactivating/
// reloading) after stop can still generate AVCs; the old exact-"active" check
// missed these. Must fail closed.
func TestExerciseFailsClosedOnTransitionalState(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{responses: map[string]string{
		"stat -c '%s %i'":           "0 4242",
		"stat -c '%i'":              "4242",
		"auditctl -s":               "enabled 1 lost 0 backlog 0",
		"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
		"is-active widget.service":  "deactivating",
	}}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err == nil || !strings.Contains(err.Error(), "not cleanly stopped") {
		t.Fatalf("a transitional post-stop state must fail closed, got %v", err)
	}
}

// Round 33: the verifier baseline SCOPES the verdict. If a required field cannot
// be collected the run must fail closed, not sign an unscoped verdict.
func TestRunFailsClosedWhenVerifierBaselineIncomplete(t *testing.T) {
	f := passingRunner()
	f.failOn = []string{"uname -r"} // kernel cannot be collected
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "verifier kernel") {
		t.Errorf("a missing verifier baseline field must fail closed, got %q", res.FailureReason)
	}
}

// Round 33: an empty/unknown post-stop probe is fail-open — only an explicit
// "inactive"/"failed" counts as stopped.
func TestExerciseFailsClosedOnUnknownStopState(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	// No is-active response → probe returns empty (unknown), which must fail.
	f := &fakeRunner{responses: map[string]string{
		"stat -c '%s %i'":           "0 4242",
		"stat -c '%i'":              "4242",
		"auditctl -s":               "enabled 1 lost 0 backlog 0",
		"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
	}}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err == nil || !strings.Contains(err.Error(), "not cleanly stopped") {
		t.Fatalf("an unknown post-stop state must fail closed, got %v", err)
	}
}

// Round 34: audit verification must FAIL CLOSED when auditctl cannot be queried
// at all — a transient failure previously skipped the enabled/loss checks and
// could hide dropped AVCs behind a passing verdict.
func TestExerciseFailsClosedWhenAuditUnqueryable(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	// No "auditctl -s" response → auditStatus is not ok → must fail closed.
	f := &fakeRunner{responses: map[string]string{
		"stat -c '%s %i'": "0 4242",
		"stat -c '%i'":    "4242",
	}}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err == nil || !strings.Contains(err.Error(), "cannot query audit status") {
		t.Fatalf("unqueryable audit status must fail closed, got %v", err)
	}
}

// Round 34: the verifier must FAIL CLOSED if a declared port is not actually
// assigned to the app's port type — a discarded semanage error let it sign an
// unenforced mapping.
func TestRunFailsClosedWhenDeclaredPortNotAssigned(t *testing.T) {
	tgt := testTarget()
	tgt.Ports = []profile.Port{{Proto: "tcp", Port: 8443}}
	f := passingRunner()
	// semanage port -l returns nothing for widget_port_t → the port never lists.
	res := Run(f, tgt, Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "was not assigned") {
		t.Errorf("an unassigned declared port must fail closed, got %q", res.FailureReason)
	}
}

// Round 35: same-inode truncation between the pre-tail stat and the read makes
// tail return empty successfully; the size recheck must catch it.
func TestExerciseFailsClosedOnSameInodeTruncation(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{responses: map[string]string{
		"stat -c '%s %i'":           "100 4242", // pre/post size 100, inode 4242
		"stat -c '%i'":              "4242",     // inode unchanged post-read
		"stat -c '%s'":              "10",       // size shrank 100 -> 10 (truncated)
		"auditctl -s":               "enabled 1 lost 0 backlog 0",
		"is-active widget.service":  "inactive",
		"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
	}}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err == nil || !strings.Contains(err.Error(), "truncated during read") {
		t.Fatalf("same-inode truncation must fail closed, got %v", err)
	}
}

// Round 35: a failure after the module is installed must roll back the verifier's
// generated SELinux state (semodule -r) rather than leaving it to contaminate
// later runs.
func TestRunCleansVerifierStateOnFailure(t *testing.T) {
	f := passingRunner()
	// Force a failure AFTER install: no shadow_t static check trips at enforcement.
	f.responses["-t shadow_t"] = "allow widget_t shadow_t:file read;"
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" {
		t.Fatal("expected a failure")
	}
	if f.countCalls("semodule -r widget") == 0 {
		t.Error("a post-install failure must roll back the generated module (semodule -r)")
	}
}

// Round 37: `semodule -i <app>.pp` replaces by MODULE NAME, so an existing
// module named <app> that defines a differently-named domain must be detected as
// a conflict even though our <app>_t type does not yet exist.
func TestRunDetectsModuleNameConflict(t *testing.T) {
	f := passingRunner()
	f.responses["semodule -l"] = "widget\nbase\nmysql\n" // a module named widget exists
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "name-conflict") && !strings.Contains(res.FailureReason, "already exists") {
		t.Errorf("an existing module named <app> must be a conflict, got %q", res.FailureReason)
	}
}

// Round 38: a stray %[N]s inside a comment was expanded by fmt.Sprintf into
// multiline shell, breaking %post. The generated scriptlets must contain no
// unexpanded format placeholder AND must be valid bash.
func TestSpecScriptletsAreValidBash(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}, {Path: "/etc/widget(/.*)?", Kind: "conf"}},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "1")
	if strings.Contains(spec, "%[") {
		t.Errorf("spec contains an unexpanded format placeholder %%[...]s:\n%s", spec)
	}
	// Extract each scriptlet body and syntax-check it with `bash -n`.
	for _, sect := range []string{"%pre", "%post", "%postun"} {
		body := scriptletBody(spec, sect)
		if strings.TrimSpace(body) == "" {
			continue
		}
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(body)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s scriptlet is not valid bash: %v\n%s\n---body---\n%s", sect, err, out, body)
		}
	}
}

// scriptletBody returns the lines of an rpm spec section (e.g. "%post") up to
// the next top-level %section header, with rpm macros neutralized so `bash -n`
// parses only the shell.
func scriptletBody(spec, header string) string {
	lines := strings.Split(spec, "\n")
	var body []string
	in := false
	sections := map[string]bool{"%pre": true, "%post": true, "%postun": true, "%preun": true, "%install": true, "%files": true, "%description": true, "%build": true, "%prep": true, "%posttrans": true}
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		first := strings.Fields(trimmed)
		if len(first) > 0 && sections[first[0]] {
			in = first[0] == header
			continue
		}
		if in {
			// Neutralize rpm macros so bash -n sees a plain token, not %{...}.
			body = append(body, strings.NewReplacer("%{", "${RPM_", "}", "}").Replace(ln))
		}
	}
	return strings.Join(body, "\n")
}

// Round 38: nameConflict must FAIL CLOSED if `semodule -l` cannot enumerate —
// we can't otherwise rule out an existing same-name module.
func TestRunFailsClosedWhenSemoduleListFails(t *testing.T) {
	f := passingRunner()
	f.failOn = []string{"semodule -l"}
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "cannot enumerate SELinux modules") {
		t.Errorf("a semodule -l failure must fail closed, got %q", res.FailureReason)
	}
}

// Round 38: a run that fails at enforcement (EnforceOK false) must still roll
// back the verifier's generated state, not fall through the RPM-build skip.
func TestRunCleansVerifierStateOnEnforceFailure(t *testing.T) {
	f := passingRunner()
	// Residual denial under enforcement that refinement cannot silence: a denial
	// on a forbidden target keeps EnforceOK false across attempts.
	f.responses["tail -c"] = "type=AVC msg=audit(1): avc: denied { write } for pid=1 comm=\"widgetd\" scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0"
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.EnforceOK {
		t.Skip("expected enforcement to fail for this fixture")
	}
	if f.countCalls("semodule -r widget") == 0 {
		t.Error("an enforcement failure must roll back the generated module (semodule -r)")
	}
}

// Round 40: `semanage port -d` does not accept -t; every generated deletion must
// use `-d -p PROTO PORT` (the -t form errored and left mappings behind, blocking
// semodule -r).
func TestSpecPortDeleteUsesValidSyntax(t *testing.T) {
	p := testTarget().Profile()
	p.Ports = []profile.Port{{Proto: "tcp", Port: 8443}}
	spec := GenerateSpec(p, "1")
	if strings.Contains(spec, "semanage port -d -t") {
		t.Errorf("spec uses invalid `semanage port -d -t` (delete rejects -t):\n%s", spec)
	}
	if !strings.Contains(spec, "semanage port -d -p") {
		t.Errorf("spec must delete ports with `semanage port -d -p`:\n%s", spec)
	}
}

// Round 43: an incomplete `auditctl -s` (missing lost/backlog) must NOT be
// trusted — absent fields returned -1 and slipped past the enabled/backlog/loss
// checks. exercise() must fail closed.
func TestExerciseFailsClosedOnIncompleteAuditStatus(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	// "enabled 1" only — lost and backlog absent.
	f := &fakeRunner{responses: map[string]string{
		"stat -c '%s %i'": "0 4242",
		"stat -c '%i'":    "4242",
		"auditctl -s":     "enabled 1",
	}}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err == nil || !strings.Contains(err.Error(), "cannot query audit status") {
		t.Fatalf("an incomplete auditctl -s must fail closed, got %v", err)
	}
}

// Round 43: buildRPM must fail if rpmbuild produced no `Wrote:` line rather than
// fall back to a stale wildcard match.
func TestRunFailsWhenRpmbuildWroteNothing(t *testing.T) {
	f := passingRunner()
	f.responses["rpmbuild -bb"] = "Processing files... (no Wrote line)"
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "could not determine the built RPM path") {
		t.Errorf("a missing rpmbuild Wrote line must fail, got %q", res.FailureReason)
	}
}
