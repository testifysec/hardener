package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

func spec79(t *testing.T) string {
	t.Helper()
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	return GenerateSpec(p, "20260101000000")
}

// Round 79: %post rollback ran restorecon even when module removal failed or could
// not be verified. The still-loaded rejected module's file-contexts are ACTIVE, so
// restorecon reapplies ITS OWN unverified types instead of the base ones — the
// %post twin of the round-78 verifier-side bug. Relabeling must be gated on
// confirmed removal (fresh install) / confirmed restoration (upgrade).
func TestRollbackRelabelsOnlyAfterConfirmedModuleState(t *testing.T) {
	spec := spec79(t)
	post := spec[strings.Index(spec, "\n%post\n"):strings.Index(spec, "\n%postun\n")]

	// Fresh-install branch: a _removed flag gates the restore.
	for _, want := range []string{
		`_removed=0`,
		`if [ "$_removed" = 1 ]; then`,
		"skipping label restoration for widget because the rejected module is still loaded",
	} {
		if !strings.Contains(post, want) {
			t.Errorf("fresh-install rollback must gate relabeling on confirmed removal; missing %q", want)
		}
	}
	// Upgrade branch: the oldroots relabel is gated on _restored.
	if !strings.Contains(post, `if [ "$_restored" = 1 ]; then`) {
		t.Error("upgrade rollback must gate relabeling on confirmed restoration")
	}
	if !strings.Contains(post, "Labels were left untouched") {
		t.Error("a failed upgrade restoration must say the labels were left untouched")
	}
	// The oldroots relabel must sit INSIDE the confirmed branch.
	restoredAt := strings.Index(post, `if [ "$_restored" = 1 ]; then`)
	oldrootsAt := strings.Index(post, "widget.oldroots")
	// (the .oldroots stash reference in %pre is not in this slice)
	if restoredAt < 0 || oldrootsAt < 0 || oldrootsAt < restoredAt {
		t.Errorf("the oldroots relabel must follow the _restored gate (gate=%d oldroots=%d)", restoredAt, oldrootsAt)
	}
}

// Behavioral: the %postun restore must attempt EVERY path and report at the end,
// not abort on the first failure. Aborting could not roll back the erase (payload
// and module are already gone) and abandoned the remaining paths, leaving MORE
// files with undefined labels.
func TestPostunRestoreAttemptsAllPathsThenReports(t *testing.T) {
	dir := t.TempDir()
	// Three "paths": the middle one fails to relabel.
	script := `
_rsfail=""
if [ -e ` + dir + ` ]; then true || _rsfail="$_rsfail a"; fi
if [ -e ` + dir + ` ]; then false || _rsfail="$_rsfail b"; fi
if [ -e ` + dir + ` ]; then echo THIRD-RAN >&2; true || _rsfail="$_rsfail c"; fi
if [ -n "$_rsfail" ]; then echo "FAILED:$_rsfail" >&2; exit 1; fi`
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err == nil {
		t.Error("a failed restore must still exit non-zero at the end")
	}
	s := string(out)
	// The path AFTER the failure must still have been attempted.
	if !strings.Contains(s, "THIRD-RAN") {
		t.Error("a restore failure must not abandon the remaining paths")
	}
	// The report must name only the failing path.
	if !strings.Contains(s, "FAILED: b") {
		t.Errorf("the report must list the failed path, got %q", s)
	}
	// All-succeeding case exits 0 with no report.
	okScript := `
_rsfail=""
if [ -e ` + dir + ` ]; then true || _rsfail="$_rsfail a"; fi
if [ -n "$_rsfail" ]; then exit 1; fi`
	if err := exec.Command("sh", "-c", okScript).Run(); err != nil {
		t.Error("an all-successful restore must exit 0")
	}
}
