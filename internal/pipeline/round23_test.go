package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 23 (#3): reconciliation must be emitted even with NO declared ports, so
// an upgrade from one port to zero still prunes the old <app>_port_t mapping
// before the new (type-less) module loads.
func TestSpecReconcilesWithNoPorts(t *testing.T) {
	p := &profile.Profile{Name: "widget", Executables: []string{"/opt/widget/bin/widgetd"}}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, `semanage port -l | awk '$1=="widget_port_t"`) {
		t.Errorf("reconcile must run even with no declared ports:\n%s", spec)
	}
	// Rollback must restore pruned mappings on upgrade failure.
	if !strings.Contains(spec, "for _row in $_pruned;") {
		t.Errorf("rollback must restore pruned port mappings:\n%s", spec)
	}
}
