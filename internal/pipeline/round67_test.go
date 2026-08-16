package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 67: cleanupVerifierState returned immediately when moduleInstalled was
// false — BEFORE the unit-quiescence block. If install/setup starts the service
// and a later step fails before the module loads, the service is left active and
// UNCONFINED (no module) on the persistent verifier. Quiescence must run on every
// post-install failure, independent of module cleanup.
func TestCleanupStopsUnitWhenModuleNotInstalled(t *testing.T) {
	f := passingRunner()
	f.responses["is-active widget.service"] = "active" // install/setup started it
	f.failOn = []string{"file_contexts"}               // fail AFTER install/setup, BEFORE module load
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" {
		t.Fatal("the run must fail when base file_contexts cannot be read")
	}
	if f.countCalls("systemctl kill -s SIGKILL widget.service") == 0 {
		t.Error("cleanup must try to stop a running unit even when no module was installed (it would otherwise be left unconfined)")
	}
	// Nothing was installed, so no SELinux teardown must run.
	if f.countCalls("semodule -r widget") != 0 {
		t.Error("no module was installed — cleanup must not run semodule -r")
	}
}

// Round 67: fcLiteralStem reduces an external file-contexts regex to its literal
// prefix so an ANCESTOR regex like /var/lib(/.+)? — which the fixed-suffix fcRoot
// leaves intact — is compared as the directory /var/lib and detected as an overlap.
func TestFCLiteralStemReducesAncestorRegex(t *testing.T) {
	cases := map[string]string{
		"/var/lib(/.+)?": "/var/lib", // the ancestor regex that bypassed fcRoot
		"/var/lib(/.*)?": "/var/lib",
		"/var/lib/.*":    "/var/lib",
		"/etc/foo[0-9]+": "/etc/foo",
		"/opt/app":       "/opt/app", // pure literal unchanged
		"/opt/app/":      "/opt/app", // trailing slash stripped
	}
	for in, want := range cases {
		if got := fcLiteralStem(in); got != want {
			t.Errorf("fcLiteralStem(%q) = %q, want %q", in, got, want)
		}
	}
}

// Round 67: the %post local-fcontext overlap awk must reduce each local entry to
// its literal stem (truncate at the first regex metacharacter), not merely strip
// the exact (/.*)? suffix — else an ancestor like /var/lib(/.+)? bypasses it. The
// check must also run BEFORE the [ -e "$_r" ] existence gate so an absent declared
// root is still protected.
func TestSpecOverlapCheckUsesLiteralStem(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	spec := GenerateSpec(p, "20260101000000")
	if !strings.Contains(spec, `m=match(p, /[].^$*+?(){}|[\\]/)`) {
		t.Error("overlap awk must reduce local entries to their literal stem (match at the first regex metacharacter)")
	}
	if strings.Contains(spec, `substr(p,length(p)-5)=="(/.*)?"`) {
		t.Error("overlap awk must no longer strip only the exact (/.*)? suffix")
	}
	// The overlap check must not be gated on the ROOT existing — a not-yet-created
	// data dir must still be protected from an overlapping local rule. Compare
	// against the root-existence gate specifically (`[ -e "$_r" ]`); other `[ -e ]`
	// guards (e.g. the entrypoint hard-link check) are unrelated.
	ov := strings.Index(spec, "_ov=$(printf")
	ex := strings.Index(spec, `[ -e "$_r" ]`)
	if ov < 0 || ex < 0 || ov > ex {
		t.Errorf("overlap check must precede the root existence gate (ov=%d ex=%d)", ov, ex)
	}
}
