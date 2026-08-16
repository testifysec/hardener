package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 70 (uninstall regression): %postun captures the port listing ONCE and
// tests every declared entry against that stale snapshot. With a duplicate
// (proto, port) the second entry still matches after the first deletion removed
// the mapping, so the second `semanage port -d` fails and the fail-closed handler
// aborts %postun BEFORE `semodule -r` and the label restore — an RPM erase that
// leaves the module and stale labels installed.
//
// Duplicates are now rejected at manifest load (see target.Load), so a generated
// spec can never contain one. This pins the property the generator must hold:
// each (proto, port) appears exactly once in the uninstall path, and the deletion
// stays fail-closed.
func TestPostunDeletesEachPortExactlyOnce(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports: []profile.Port{
			{Proto: "tcp", Port: 8443},
			{Proto: "udp", Port: 5353},
		},
	}
	spec := GenerateSpec(p, "20260101000000")
	postun := spec[strings.Index(spec, "\n%postun\n"):]

	for _, want := range []struct {
		frag string
		n    int
	}{
		{"semanage port -d -p tcp 8443", 1},
		{"semanage port -d -p udp 5353", 1},
	} {
		if got := strings.Count(postun, want.frag); got != want.n {
			t.Errorf("postun contains %q %d times, want %d — a repeated deletion re-runs against the stale listing and aborts the uninstall", want.frag, got, want.n)
		}
	}
	// The snapshot is captured once and validated before any deletion, and the
	// deletion itself stays fail-closed (round-63 behavior must not regress).
	for _, want := range []string{
		`_pl="$(semanage port -l 2>/dev/null)"`,
		"refusing to leave a stale bind privilege",
	} {
		if !strings.Contains(postun, want) {
			t.Errorf("postun missing %q", want)
		}
	}
}
