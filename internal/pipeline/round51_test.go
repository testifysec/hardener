package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// The %post fresh-install guard must preflight the PORT type, not only the
// module name: a differently-named foreign module can own <app>_port_t, and the
// port reconciliation would DELETE its mappings before semodule -i fails on the
// duplicate type. Portable check via semanage port -l (not setools/seinfo).
// (review finding — round 51)
func TestSpecPostPreflightsForeignPortType(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "20260101000000")
	for _, want := range []string{
		`awk -v t=widget_port_t '$1==t{f=1} END{exit !f}'`,
		"a foreign module owns it",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("%%post fresh-install guard missing port-type preflight %q", want)
		}
	}

	// Behavioral: the preflight awk exits 0 (foreign owner present) when a row
	// for our port type exists, and non-zero otherwise.
	prog := `$1==t{f=1} END{exit !f}`
	cases := []struct {
		portList string
		foreign  bool
	}{
		{"SELinux Port Type    Proto    Port Number\nwidget_port_t        tcp      8443", true},
		{"SELinux Port Type    Proto    Port Number\nssh_port_t           tcp      22", false},
		{"SELinux Port Type    Proto    Port Number\nhttp_port_t          tcp      80, 443", false},
	}
	for _, c := range cases {
		cmd := exec.Command("awk", "-v", "t=widget_port_t", prog)
		cmd.Stdin = strings.NewReader(c.portList + "\n")
		err := cmd.Run()
		found := err == nil // exit 0 → foreign owner present
		if found != c.foreign {
			t.Errorf("port list %q: foreign=%v want %v", c.portList, found, c.foreign)
		}
	}
}

// %post rollback must VERIFY module restoration, not suppress every failure with
// `|| :`: a failed old-module restore on upgrade (or a rejected module left
// loaded on fresh install) leaves the app under absent/unverified policy while
// RPM only reports failure. The rollback must report those states loudly with a
// manual remediation. (review finding — round 59)
func TestSpecRollbackVerifiesModuleRestoration(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "20260101000000")
	for _, want := range []string{
		"rejected widget policy module is still loaded after rollback",
		// Fresh-install branch CAPTURES semodule -l and fails closed if it could
		// not enumerate (piping straight into grep was fail-open).
		"cannot verify removal of the rejected widget policy module",
		"_ml=\"$(semodule -l 2>/dev/null)\"",
		// Upgrade branch verifies CONTENT against the snapshot, not just the name
		// (the rejected module shares the name): re-extract and diff against $_snap.
		"content did not match the pre-upgrade snapshot",
		"diff -rq \"$_snap\" \"$_vfy\"",
		`grep -qE "^widget([[:space:]]|$)"`,
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("rollback must verify module restoration; missing %q", want)
		}
	}
}

// %postun must CAPTURE and validate the port listing before deletion (piping an
// unvalidated `semanage port -l` into awk|grep is fail-open — a failed
// enumeration skips deletion, semodule -r then fails on the referenced type, and
// RPM removal "succeeds" leaving the module + stale bind privilege). It must also
// VERIFY module removal. (review finding — round 63)
func TestSpecPostunValidatesPortCleanupAndModuleRemoval(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "20260101000000")
	for _, want := range []string{
		`_pl="$(semanage port -l 2>/dev/null)"`,
		"cannot enumerate SELinux ports during widget_port_t uninstall",
		"refusing to leave a stale bind privilege",                    // port deletion fails closed
		"the widget policy module is still installed after uninstall", // module removal verified
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("%%postun missing validated cleanup: %q", want)
		}
	}
	// The old fail-open form (piping semanage port -l straight into awk in %postun)
	// must be gone.
	if strings.Contains(spec, "if semanage port -l 2>/dev/null | awk -v t=widget_port_t") {
		t.Error("postun still pipes an unvalidated semanage port -l into awk")
	}
}
