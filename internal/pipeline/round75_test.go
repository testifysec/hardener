package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 75 (regression from round 67): fail() also fires for PRE-install failures
// — precheck and name-conflict both return before t.Install runs. Making unit
// quiescence unconditional meant those paths SIGKILLed a same-named service that
// hardener had never touched, which on a persistent verifier is somebody else's
// running workload. Quiescence must be gated on having actually started.
func TestPreInstallFailureLeavesForeignUnitAlone(t *testing.T) {
	f := passingRunner()
	f.responses["is-active widget.service"] = "active" // a foreign service is running
	// Force a name-conflict failure, which returns BEFORE t.Install.
	f.responses["seinfo -t widget_t"] = "Types: 1\n   widget_t\n"
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "already exists") {
		t.Fatalf("expected a name-conflict failure, got %q", res.FailureReason)
	}
	if n := f.countCalls("systemctl kill -s SIGKILL widget.service"); n != 0 {
		t.Errorf("a pre-install failure must not SIGKILL a unit hardener never touched (kill calls=%d)", n)
	}
	if n := f.countCalls("systemctl stop widget.service"); n != 0 {
		t.Errorf("a pre-install failure must not stop a unit hardener never touched (stop calls=%d)", n)
	}
}

// ...but once install has been attempted, a failure MUST still quiesce the unit
// (the round-67 behavior this gate must not undo).
func TestPostInstallFailureStillStopsUnit(t *testing.T) {
	f := passingRunner()
	f.responses["is-active widget.service"] = "active"
	f.failOn = []string{"file_contexts"} // fails AFTER install/setup
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" {
		t.Fatal("expected a failure")
	}
	if f.countCalls("systemctl kill -s SIGKILL widget.service") == 0 {
		t.Error("a post-install failure must still try to stop the unit")
	}
}

// Round 75: in %postun a restorecon failure was reduced to a warning, so the erase
// SUCCEEDED while existing files kept now-undefined app types — dangling labels
// that can make those files inaccessible, with the module already gone. An absent
// path is skipped; an existing path that cannot be relabeled fails the uninstall.
// Best-effort remains correct in the %post ROLLBACK paths.
func TestPostunLabelRestoreFailsClosed(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	spec := GenerateSpec(p, "20260101000000")
	postun := spec[strings.Index(spec, "\n%postun\n"):]
	// Round 79 refined this: still fail closed, but attempt EVERY path first and
	// report at the end. Aborting on the first failure could not roll back the
	// erase and abandoned the remaining paths, leaving MORE files undefined.
	for _, want := range []string{
		"if [ -e '/var/lib/widget' ]; then restorecon -RF -- '/var/lib/widget' || _rsfail=",
		"those files keep an undefined type and may be inaccessible",
		`if [ -n "$_rsfail" ]; then`,
	} {
		if !strings.Contains(postun, want) {
			t.Errorf("postun label restore must collect failures then fail closed; missing %q", want)
		}
	}
	// No early exit between the per-path restores.
	firstRestore := strings.Index(postun, "restorecon -RF -- '/var/lib/widget'")
	report := strings.Index(postun, `if [ -n "$_rsfail" ]`)
	if firstRestore < 0 || report < 0 || firstRestore > report {
		t.Error("the failure report must come after all per-path restores")
	}
	if strings.Contains(postun, "restorecon -RF -- '/var/lib/widget' || { echo") {
		t.Error("postun must no longer abort on the first restore failure")
	}
	if strings.Contains(postun, "warning: could not restore some widget file labels") {
		t.Error("postun must no longer downgrade a label-restore failure to a warning")
	}
	// The %post ROLLBACK paths keep best-effort restores — they are already
	// handling a failure and must finish their remaining steps.
	post := spec[strings.Index(spec, "\n%post\n"):strings.Index(spec, "\n%postun\n")]
	if !strings.Contains(post, "warning: could not restore some widget file labels") {
		t.Error("the post rollback path must keep its best-effort restore")
	}
}

// Behavioral error path: skip when absent, fail when present-but-unrelabelable.
func TestPostunRestoreGuardBehavior(t *testing.T) {
	dir := t.TempDir()
	guard := func(path, cmd string) error {
		return exec.Command("sh", "-c",
			"if [ -e "+path+" ]; then "+cmd+" || { echo ERROR >&2; exit 1; }; fi").Run()
	}
	// Absent path → skipped, exit 0 even though the command would fail.
	if err := guard(dir+"/missing", "false"); err != nil {
		t.Error("an absent path must be skipped, not fail the uninstall")
	}
	// Existing path whose relabel fails → uninstall fails.
	if err := guard(dir, "false"); err == nil {
		t.Error("an existing path that cannot be relabeled must fail the uninstall")
	}
	// Existing path whose relabel succeeds → ok.
	if err := guard(dir, "true"); err != nil {
		t.Error("a successful relabel must not fail the uninstall")
	}
}
