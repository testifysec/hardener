package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 15: an entrypoint whose exact path the base policy already labels
// cannot receive <app>_exec_t, so the init→domain transition never fires and
// the service runs unconfined — while restorecon still exits 0. This must FAIL
// the run, not silently ship an unconfining policy.
func TestExecutableCollisionIsFatal(t *testing.T) {
	f := passingRunner()
	// Base policy already labels the widget entrypoint as bin_t.
	f.responses["contexts/files/file_contexts"] = "/opt/widget/bin/widgetd\t--\tsystem_u:object_r:bin_t:s0\n"
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" || !strings.Contains(res.FailureReason, "collision") {
		t.Errorf("an entrypoint label collision must fail the run, got %q", res.FailureReason)
	}
	if res.RPMPath != "" {
		t.Errorf("no artifact may be packaged after a fatal entrypoint collision")
	}
}

// A collision on a DATA path (not an entrypoint) stays recoverable: it is
// dropped from the profile and reported, and the run proceeds.
func TestDataPathCollisionIsNotFatal(t *testing.T) {
	f := passingRunner()
	// Base policy claims the var_lib path, but NOT the entrypoint.
	f.responses["contexts/files/file_contexts"] = "/var/lib/widget(/.*)?\tsystem_u:object_r:var_log_t:s0\n"
	tgt := testTarget()
	tgt.Paths = []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}}
	res := Run(f, tgt, Options{MaxRounds: 2})
	if res.FailureReason != "" && strings.Contains(res.FailureReason, "collision") {
		t.Errorf("a data-path collision must not fail the run: %q", res.FailureReason)
	}
	if len(res.Collisions) == 0 {
		t.Error("the data-path collision should still be reported")
	}
}
