package pipeline

import (
	"strings"
	"testing"
)

// Round 18 (#2): DomainOK proves the MainPID carries our domain label, but the
// verdict must also bind the bytes that ACTUALLY ran. A running binary whose
// digest differs from the declared entrypoint fails.
func TestRunningExeDigestMustMatch(t *testing.T) {
	f := passingRunner()
	f.responses["systemctl show -p MainPID"] = "LABEL:system_u:system_r:widget_t:s0\n" +
		"EXE:/opt/widget/bin/widgetd\n" +
		"EXESHA:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "running-exe-mismatch") {
		t.Errorf("a running binary whose digest differs from the declared entrypoint must fail, got %q", res.FailureReason)
	}
}

// A process in our domain whose /proc/$pid/exe is not a declared entrypoint at
// all must fail — the verdict cannot bind digests for bytes never exercised.
func TestRunningExeMustBeDeclared(t *testing.T) {
	f := passingRunner()
	f.responses["systemctl show -p MainPID"] = "LABEL:system_u:system_r:widget_t:s0\n" +
		"EXE:/usr/bin/somethingelse\n" +
		"EXESHA:abababababababababababababababababababababababababababababababab"
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "running-exe-unbound") {
		t.Errorf("a running binary that is not a declared entrypoint must fail, got %q", res.FailureReason)
	}
}

// Round 18 (#3): hardener must refuse to SHADOW an existing SELinux policy of
// the same name (e.g. sshd_t already defined by the distro).
func TestRefusesToShadowExistingPolicy(t *testing.T) {
	f := passingRunner()
	f.responses["sesearch -A -s widget_t -c process"] = "allow widget_t widget_t:process { fork };"
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "name-conflict") {
		t.Errorf("must refuse to shadow an existing policy, got %q", res.FailureReason)
	}
}
