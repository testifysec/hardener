package pipeline

import (
	"testing"
)

// A unit that refuses to stop (stays active) must NOT have its confinement torn
// down: removing the module/ports/permissive around a live process leaves it
// UNCONFINED. Cleanup force-kills first, and if the unit still cannot be proven
// dead it PRESERVES the module. (review finding — round 53)
func TestCleanupPreservesModuleWhenUnitStaysAlive(t *testing.T) {
	f := passingRunner()
	f.responses["is-active widget.service"] = "active" // resists stop, stays live throughout
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" {
		t.Fatal("a unit that will not stop must fail the run")
	}
	if f.countCalls("systemctl kill -s SIGKILL widget.service") == 0 {
		t.Error("cleanup must attempt a force-kill before deciding")
	}
	if f.countCalls("semodule -r widget") != 0 {
		t.Error("cleanup must PRESERVE the module while the confined unit is still alive (no semodule -r)")
	}
}

// Conversely, once the unit is confirmed stopped, cleanup proceeds and removes
// the module as before (guards against the quiescence gate over-preserving).
func TestCleanupRemovesModuleWhenUnitIsStopped(t *testing.T) {
	f := passingRunner()                                              // is-active → "inactive"
	f.responses["-t shadow_t"] = "allow widget_t shadow_t:file read;" // force a post-exercise failure
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" {
		t.Fatal("expected a failure")
	}
	if f.countCalls("semodule -r widget") == 0 {
		t.Error("a stopped unit must still have its module removed on failure cleanup")
	}
}
