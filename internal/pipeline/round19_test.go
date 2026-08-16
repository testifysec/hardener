package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 19 (#2): a rotation between the pre-read stat and the tail would let
// tail read the NEW file at the stale offset and return an empty slice — a false
// zero-denial pass. The post-read inode re-check must catch it and fail closed.
func TestAuditRotationDuringReadFailsClosed(t *testing.T) {
	f := passingRunner()
	f.responses["stat -c '%i'"] = "9999" // inode changed across the read
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "rotated during read") {
		t.Errorf("a rotation during the audit read must fail closed, got %q", res.FailureReason)
	}
}

// Round 19 (#4): the %post rollback must only run on a FRESH install. On an
// upgrade it must restore the PRIOR module (round 22), never destroy the working
// installation or leave the service unconfined.
func TestSpecRollbackIsUpgradeSafe(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "1")
	// Fresh-install removes the module; upgrade snapshots and restores it.
	if !strings.Contains(spec, `if [ "$_op" = 1 ]; then`) {
		t.Errorf("rollback must branch fresh-install vs upgrade:\n%s", spec)
	}
	if !strings.Contains(spec, "semodule -E %[1]s") && !strings.Contains(spec, "semodule -E widget") {
		t.Errorf("upgrade must snapshot the previous module for restore:\n%s", spec)
	}
}
