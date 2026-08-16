package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/vm"
)

// #1: a manifest path with shell metacharacters must be SINGLE-quoted in the
// generated %post — %q's double quotes still expand $()/backticks, which would
// execute under the customer's (or CI's passwordless-sudo) install.
func TestSpecSingleQuotesMaliciousPaths(t *testing.T) {
	evil := "/opt/widget/bin/$(touch PWNED)"
	p := &profile.Profile{Name: "widget", Executables: []string{evil}}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, vm.ShellQuote(evil)) {
		t.Errorf("entrypoint path must be single-quoted in spec:\n%s", spec)
	}
	if strings.Contains(spec, `"`+evil+`"`) {
		t.Error("entrypoint path must NOT be double-quoted (allows $() execution)")
	}
}

// #5: the %post must verify the entrypoint's RESULTING SELinux type, not just
// restorecon's exit status (a higher-priority fcontext can apply another type).
func TestSpecVerifiesEntrypointType(t *testing.T) {
	p := &profile.Profile{Name: "widget", Executables: []string{"/opt/widget/bin/widgetd"}}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, "stat -c '%C'") || !strings.Contains(spec, "not widget_exec_t") {
		t.Errorf("spec must verify the resulting exec type:\n%s", spec)
	}
}

// #6: different policy revisions must produce different RPM Releases, so changed
// content never shares a NEVRA with the prior build.
func TestSpecRevisionChangesRelease(t *testing.T) {
	p := &profile.Profile{Name: "widget", Executables: []string{"/opt/widget/bin/widgetd"}}
	a := GenerateSpec(p, "20260101000000")
	b := GenerateSpec(p, "20260102000000")
	if a == b {
		t.Fatal("different revisions must yield different specs")
	}
	if !strings.Contains(a, "Release:        1.20260101000000") ||
		!strings.Contains(b, "Release:        1.20260102000000") {
		t.Error("Release must carry the revision")
	}
}

// #2: an entrypoint whose bytes cannot be hashed must FAIL the run — never a
// silent skip that leaves a passing verdict binding no digest for it.
func TestEntrypointDigestFailsClosed(t *testing.T) {
	f := passingRunner()
	f.failOn = []string{"sha256sum"} // cannot hash the entrypoint
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "entrypoint-digest") {
		t.Errorf("an unhashable entrypoint must fail the run, got %q", res.FailureReason)
	}
}

// #3: any return after the domain is made permissive must still remove it from
// the persistent verifier's permissive list (a leak leaves every future run on
// that box permissive).
func TestPermissiveClearedOnErrorPath(t *testing.T) {
	f := passingRunner()
	f.failOn = []string{"EXERCISE_MARKER"} // error after `permissive -a`
	tgt := testTarget()
	tgt.Exercise = "EXERCISE_MARKER"
	res := Run(f, tgt, Options{MaxRounds: 2})
	if res.FailureReason == "" {
		t.Fatal("expected a failure")
	}
	if n := f.countCalls("semanage permissive -d"); n < 1 {
		t.Errorf("domain must be removed from the permissive list on the error path, -d calls=%d", n)
	}
}
