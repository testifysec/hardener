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
	// Round 28: the listing is captured and validated before the awk loop (fail
	// closed on enumeration error), so it no longer inlines `semanage port -l | awk`.
	if !strings.Contains(spec, `_portlist="$(semanage port -l 2>/dev/null)"`) ||
		!strings.Contains(spec, `awk '$1=="widget_port_t"`) {
		t.Errorf("reconcile must capture the listing and run even with no declared ports:\n%s", spec)
	}
	// Rollback must restore pruned mappings on upgrade failure.
	if !strings.Contains(spec, "for _row in $_pruned;") {
		t.Errorf("rollback must restore pruned port mappings:\n%s", spec)
	}
}

// Round 24 (#3): an upgrade must reconcile REMOVED file-context roots — stash
// the old roots in %pre and restore base labels on those the new profile drops.
func TestSpecReconcilesRemovedRoots(t *testing.T) {
	p := &profile.Profile{Name: "widget", Paths: []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}}}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, "%pre") || !strings.Contains(spec, ".oldroots") {
		t.Errorf("upgrade must stash old roots in %%pre:\n%s", spec)
	}
	if !strings.Contains(spec, "restore removed root") {
		t.Errorf("%%post must reconcile removed roots:\n%s", spec)
	}
}

// Round 24 (#4): an upgrade whose module snapshot fails must ABORT before
// mutating anything, not proceed with a non-atomic fallback.
func TestSpecUpgradeAbortsWithoutSnapshot(t *testing.T) {
	p := &profile.Profile{Name: "widget", Executables: []string{"/opt/widget/bin/widgetd"}}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, "refusing a non-atomic upgrade") {
		t.Errorf("%%post must abort if the module snapshot fails:\n%s", spec)
	}
}
