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
