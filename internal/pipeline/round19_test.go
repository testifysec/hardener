package pipeline

import (
	"strings"
	"testing"
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
