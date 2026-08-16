package pipeline

import (
	"strings"
	"testing"
)

// passingRunner scripts a run that clears install, observation (no denials,
// exercise ok), and enforcement (domain label present, no residuals).
func passingRunner() *fakeRunner {
	return &fakeRunner{responses: map[string]string{
		"getenforce":                "Enforcing\nactive",
		"stat -c '%s %i'":           "0 4242",
		"stat -c '%i'":              "4242",
		"stat -c %h":                "1", // single hard link (not a shared inode)
		"auditctl -s":               "enabled 1 lost 0 backlog 0",
		"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:abababababababababababababababababababababababababababababababab",
		"command -v sesearch":       "TOOLS_OK",
		"sesearch -A -s init_t":     "allow init_t bin_t:file execute;",
		"sha256sum":                 "abababababababababababababababababababababababababababababababab  /home/u/rpmbuild/RPMS/noarch/widget-selinux-1.0.0-1.el9.noarch.rpm",
		"ls ~/rpmbuild/RPMS/noarch": "/home/u/rpmbuild/RPMS/noarch/widget-selinux-1.0.0-1.el9.noarch.rpm",
	}}
}

// A failing sesearch static check must fail the run, not just decorate the
// report. sesearch output on the shadow_t query simulates a policy that
// grants forbidden access.
func TestUnacceptedStaticCheckFailureFailsTheRun(t *testing.T) {
	f := passingRunner()
	f.responses["-t shadow_t"] = "allow widget_t shadow_t:file read;"
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" || !strings.Contains(res.FailureReason, "shadow_t") {
		t.Errorf("static-check failure must fail the run, got %q", res.FailureReason)
	}
	if res.RPMPath != "" {
		t.Errorf("no artifact may be packaged after a failed static check")
	}
}

// rpmbuild failure must fail the run: a passing verdict with no subject is an
// attestation about nothing.
func TestRPMBuildFailureFailsTheRun(t *testing.T) {
	f := passingRunner()
	f.failOn = []string{"rpmbuild -bb"}
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" || !strings.Contains(res.FailureReason, "rpmbuild") {
		t.Errorf("rpm build failure must fail the run, got %q", res.FailureReason)
	}
}

// The generated spec must not suppress semodule failure in %post.
func TestSpecFailsClosedOnSemodule(t *testing.T) {
	spec := GenerateSpec(testTarget().Profile(), "20260101000000")
	if strings.Contains(spec, "semodule -i %{_datadir}/selinux/packages/widget.pp || :") {
		t.Error("post scriptlet suppresses semodule failure — package would install unconfined")
	}
	if !strings.Contains(spec, "if ! semodule -i") {
		t.Errorf("spec missing fail-closed semodule guard:\n%s", spec)
	}
}
