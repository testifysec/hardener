package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
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

// Round 18 (#4): %post must roll back the module and port mappings on any
// post-load failure, not leave partial state behind.
func TestSpecPostRollsBackOnFailure(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, "trap _rollback EXIT") || !strings.Contains(spec, "_ok=1") {
		t.Errorf("%%post must arm a rollback trap and disarm only on full success:\n%s", spec)
	}
}

// Round 18 (#5): %postun must restore base file labels after removing the module
// (else files keep undefined app labels and become inaccessible), depend on
// policycoreutils-python-utils for semanage, and not silence cleanup failures.
func TestSpecPostunRestoresLabels(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget", Kind: "var_lib"}},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, "Requires(postun): policycoreutils policycoreutils-python-utils") {
		t.Error("postun must depend on policycoreutils-python-utils for semanage")
	}
	if !strings.Contains(spec, "could not restore") {
		t.Errorf("postun must restore file labels after module removal:\n%s", spec)
	}
	// Port removal on uninstall must be observable, not '|| :'.
	if strings.Contains(spec, "port -d -t widget_port_t -p tcp 8443 2>/dev/null || :") {
		t.Errorf("postun port removal must be observable, not silenced:\n%s", spec)
	}
}
