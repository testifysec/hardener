package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 77: %pre skipped absent entrypoints while %post ran restorecon+stat on
// them unconditionally, so a missing binary failed only AFTER rpm committed the
// payload and NEVRA — making a retry of the same NEVRA a no-op. %pre must require
// each entrypoint to exist and be stat-able.
func TestPreRequiresEntrypointsToExist(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
	}
	spec := GenerateSpec(p, "20260101000000")
	pre := spec[strings.Index(spec, "\n%pre\n"):]
	pre = pre[:strings.Index(pre, "\n%post\n")]
	for _, want := range []string{
		`if [ ! -e "$_e" ]; then`,
		"does not exist; install the application before its policy package",
		"cannot stat entrypoint",
	} {
		if !strings.Contains(pre, want) {
			t.Errorf("pre scriptlet must require entrypoint existence; missing %q", want)
		}
	}
	// The old skip-if-absent form must be gone.
	if strings.Contains(pre, `if [ -e "$_e" ]; then _lc=`) {
		t.Error("pre scriptlet must no longer skip an absent entrypoint")
	}

	// Behavioral error path for the EXISTENCE gate (what round 77 changed). The
	// link-count step uses GNU `stat -c`, which does not exist on every dev host,
	// so it is stubbed here as LINKS — its real behavior is covered on the verifier
	// VM by the round-73 hard-link tests.
	dir := t.TempDir()
	guard := func(path, links string) error {
		return exec.Command("sh", "-c",
			`_e=`+path+`
if [ ! -e "$_e" ]; then exit 1; fi
_lc=`+links+` || exit 1
case "$_lc" in 1) : ;; *) exit 1 ;; esac`).Run()
	}
	if err := guard(dir+"/nonexistent", "1"); err == nil {
		t.Error("an absent entrypoint must fail the pre scriptlet")
	}
	if err := exec.Command("sh", "-c", "echo x > "+dir+"/bin").Run(); err != nil {
		t.Fatal(err)
	}
	if err := guard(dir+"/bin", "1"); err != nil {
		t.Error("a present, single-link entrypoint must pass")
	}
	// An unstattable link count must fail rather than be skipped.
	if err := guard(dir+"/bin", "$(false)"); err == nil {
		t.Error("an unstattable entrypoint must fail the pre scriptlet")
	}
	// A shared inode (link count > 1) must still fail.
	if err := guard(dir+"/bin", "2"); err == nil {
		t.Error("a hard-linked entrypoint must fail the pre scriptlet")
	}
}

// Round 77: the fresh-install <app>_port_t ownership guard must be emitted ONLY
// when the profile declares ports. A portless profile never defines that type,
// and since round 76 reconciliation leaves mappings it cannot prove were ours
// alone — so rejecting a legitimate foreign owner would block an install for no
// reason.
func TestPortOwnershipGuardOnlyWhenPortsDeclared(t *testing.T) {
	withPorts := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	portless := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
	}
	const marker = "already has mappings but this is a fresh install"
	if got := strings.Count(GenerateSpec(withPorts, "20260101000000"), marker); got != 2 {
		t.Errorf("a ported profile must keep the guard in both pre and post (found %d)", got)
	}
	if got := strings.Count(GenerateSpec(portless, "20260101000000"), marker); got != 0 {
		t.Errorf("a portless profile must not emit the port-ownership guard (found %d)", got)
	}
	// The module-name guard is unconditional and must survive in both.
	for _, p := range []*profile.Profile{withPorts, portless} {
		if !strings.Contains(GenerateSpec(p, "20260101000000"), "refusing to shadow a foreign module") {
			t.Error("the same-name module guard must be emitted regardless of ports")
		}
	}
}

// Round 77: the VERIFIER-side compile reused /tmp/hardener/<app>/<app>.pp without
// deleting prior outputs. make is timestamp-driven and target-controlled
// Install/Setup/Exercise all run before later compilations, so a future-dated .pp
// planted there would be loaded and verified while FinalTE and the shipped RPM
// describe different policy. Same hole closed on the packaging side in round 68.
func TestInstallPolicyForcesCleanCompile(t *testing.T) {
	f := passingRunner()
	if res := Run(f, testTarget(), Options{MaxRounds: 2}); res.FailureReason != "" {
		t.Fatalf("fixture must pass: %s", res.FailureReason)
	}
	var compile string
	for _, c := range f.calls {
		if strings.Contains(c, "make -f /usr/share/selinux/devel/Makefile") && strings.Contains(c, "semodule -i") {
			compile = c
			break
		}
	}
	if compile == "" {
		t.Fatal("no verifier compile+install script was run")
	}
	if !strings.Contains(compile, "rm -rf tmp widget.pp") {
		t.Error("the verifier compile must delete prior build outputs so make cannot skip compilation")
	}
	if !strings.Contains(compile, "test -f widget.pp") {
		t.Error("the verifier compile must assert the .pp exists after make")
	}
	if strings.Index(compile, "rm -rf tmp") > strings.Index(compile, "make -f") {
		t.Error("the removal must precede make")
	}
}
