package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

func pkgProfile() *profile.Profile {
	return &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
		Ports:       []profile.Port{{Proto: "tcp", Port: 18443}},
	}
}

// A runner where the package installs and behaves correctly.
func pkgRunner() *fakeRunner {
	return &fakeRunner{responses: map[string]string{
		"semodule -l":                               "base\nselinux-policy\nunconfined\n",
		"semodule --list-modules=full":              "100 selinux-policy pp\n200 widget            pp",
		"stat -c '%C' -- '/opt/widget/bin/widgetd'": "unconfined_u:object_r:widget_exec_t:s0",
		"if [ -e '/var/lib/widget' ]; then stat -c '%C' -- '/var/lib/widget'": "unconfined_u:object_r:widget_var_lib_t:s0",
		"ls -Zd": "system_u:object_r:bin_t:s0 /opt/widget/bin/widgetd",
	}, seq: map[string][]string{
		// Mapped while installed; gone after the erase.
		"semanage port -l": {
			"SELinux Port Type   Proto   Port Number\nwidget_port_t       tcp     18443",
			"SELinux Port Type   Proto   Port Number\nssh_port_t          tcp     22",
		},
	}}
}

// The happy path: every property the package must deliver is proven, and the
// erase is proven to undo it.
func TestVerifyPackageProvesInstallAndErase(t *testing.T) {
	checks, err := verifyPackage(pkgRunner(), pkgProfile(), "/tmp/widget-selinux.rpm")
	if err != nil {
		t.Fatalf("verifyPackage: %v", err)
	}
	want := []string{
		"rpm install",
		"module installed at priority 200",
		"entrypoint labeled widget_exec_t",
		"declared root labeled widget_var_lib_t",
		"port 18443/tcp mapped to widget_port_t",
		"rpm erase",
		"module removed after erase",
		"port mappings removed after erase",
		"entrypoint label restored after erase",
	}
	for _, w := range want {
		found := false
		for _, c := range checks {
			if strings.Contains(c.Name, w) {
				found = true
				if !c.Passed {
					t.Errorf("check %q should pass, detail=%q", c.Name, c.Detail)
				}
			}
		}
		if !found {
			t.Errorf("no check covering %q", w)
		}
	}
}

// The staged module from the observe/enforce phase sits at priority 400 and would
// SHADOW the RPM's priority-200 copy, so every check would measure the wrong
// thing. Verification must refuse to run until it is unloaded.
func TestVerifyPackageRefusesWhileStagedModuleLoaded(t *testing.T) {
	f := pkgRunner()
	f.responses["semodule -l"] = "base\nselinux-policy\nwidget\n" // never goes away
	_, err := verifyPackage(f, pkgProfile(), "/tmp/widget-selinux.rpm")
	if err == nil || !strings.Contains(err.Error(), "still loaded") {
		t.Fatalf("must refuse to measure the staged module instead of the RPM, got %v", err)
	}
}

// %selinux_modules_install swallows every error, so "rpm -i exited 0" proves
// nothing on its own. A module that never reached the store must be caught.
func TestVerifyPackageCatchesSilentModuleInstallFailure(t *testing.T) {
	f := pkgRunner()
	f.responses["semodule --list-modules=full"] = "100 selinux-policy pp" // ours absent
	checks, err := verifyPackage(f, pkgProfile(), "/tmp/widget-selinux.rpm")
	if err != nil {
		t.Fatalf("verifyPackage: %v", err)
	}
	for _, c := range checks {
		if strings.Contains(c.Name, "priority 200") && c.Passed {
			t.Error("a module missing from the store must not pass, even when rpm -i succeeded")
		}
	}
}

// The load-bearing label: without <app>_exec_t the domain transition never fires
// and the service runs unconfined while every command reports success.
func TestVerifyPackageCatchesUnlabeledEntrypoint(t *testing.T) {
	f := pkgRunner()
	f.responses["stat -c '%C' -- '/opt/widget/bin/widgetd'"] = "unconfined_u:object_r:bin_t:s0"
	checks, _ := verifyPackage(f, pkgProfile(), "/tmp/widget-selinux.rpm")
	for _, c := range checks {
		if strings.Contains(c.Name, "entrypoint labeled") && c.Passed {
			t.Error("an entrypoint left at bin_t must fail — the service would run unconfined")
		}
	}
}

// The bug that only a real install could surface: %selinux_relabel_post lives in
// %posttrans, which does NOT run on erase, so without an explicit restore the
// app's files keep a now-undefined type and the kernel reports unlabeled_t.
func TestVerifyPackageCatchesUnlabeledAfterErase(t *testing.T) {
	f := pkgRunner()
	f.responses["ls -Zd"] = "system_u:object_r:unlabeled_t:s0 /opt/widget/bin/widgetd"
	checks, _ := verifyPackage(f, pkgProfile(), "/tmp/widget-selinux.rpm")
	for _, c := range checks {
		if strings.Contains(c.Name, "restored after erase") && c.Passed {
			t.Error("unlabeled_t after erase must fail: the file may be inaccessible")
		}
	}
}

// A stale port mapping after erase leaves a bind privilege behind.
func TestVerifyPackageCatchesStalePortAfterErase(t *testing.T) {
	f := pkgRunner()
	f.seq = map[string][]string{
		"semanage port -l": {
			"SELinux Port Type   Proto   Port Number\nwidget_port_t       tcp     18443",
			"SELinux Port Type   Proto   Port Number\nwidget_port_t       tcp     18443",
		},
	}
	checks, _ := verifyPackage(f, pkgProfile(), "/tmp/widget-selinux.rpm")
	for _, c := range checks {
		if strings.Contains(c.Name, "port mappings removed") && c.Passed {
			t.Error("a mapping still present after erase must fail")
		}
	}
}

// A root the app creates on first run legitimately does not exist at install time.
func TestVerifyPackageToleratesAbsentDeclaredRoot(t *testing.T) {
	f := pkgRunner()
	f.responses["if [ -e '/var/lib/widget' ]; then stat -c '%C' -- '/var/lib/widget'"] = "ABSENT"
	checks, _ := verifyPackage(f, pkgProfile(), "/tmp/widget-selinux.rpm")
	for _, c := range checks {
		if strings.Contains(c.Name, "declared root") && !c.Passed {
			t.Errorf("an absent root must not fail the package: %s", c.Detail)
		}
	}
}

// A package that will not install at all is a hard failure, not a soft check.
func TestVerifyPackageFailsWhenRPMWillNotInstall(t *testing.T) {
	f := pkgRunner()
	f.failOn = []string{"rpm -i"}
	_, err := verifyPackage(f, pkgProfile(), "/tmp/widget-selinux.rpm")
	if err == nil || !strings.Contains(err.Error(), "does not install") {
		t.Fatalf("an uninstallable RPM must fail the run, got %v", err)
	}
}

// The whole point of the stage: a package that fails verification must fail the
// RUN, so a broken package can never carry a passing verdict.
func TestBrokenPackageFailsTheRun(t *testing.T) {
	f := passingRunner()
	f.responses["semodule --list-modules=full"] = "100 selinux-policy pp" // module never lands
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" {
		t.Fatal("a package that does not deliver its module must fail the run")
	}
	if !strings.Contains(res.FailureReason, "package-verify") {
		t.Errorf("failure should name the package stage, got %q", res.FailureReason)
	}
	if res.PackageOK {
		t.Error("PackageOK must be false")
	}
}
