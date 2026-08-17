package pipeline

import (
	"strings"
	"testing"
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
