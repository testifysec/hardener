package pipeline

import (
	"testing"
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
