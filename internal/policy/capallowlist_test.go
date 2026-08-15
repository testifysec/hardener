package policy

import (
	"testing"

	"github.com/testifysec/hardener/internal/avc"
)

// The capability gate is an allowlist, not a blocklist: any capability not on
// the tiny safe list goes to review. A blocklist silently passed
// audit_control, bpf, perfmon, setpcap, setfcap, etc.
func TestAllCapabilitiesFlaggedExceptAllowlist(t *testing.T) {
	p := widgetProfile()
	mustFlag := []string{"audit_control", "bpf", "perfmon", "setpcap", "setfcap", "sys_admin", "net_admin", "chown"}
	for _, c := range mustFlag {
		for _, class := range []string{"capability", "capability2"} {
			ds := []avc.Denial{{SourceType: "widget_t", TargetType: "widget_t", Class: class, Perms: []string{c}}}
			if res := Refine(p, ds); len(res.Flags) != 1 {
				t.Errorf("class %s cap %q must be flagged, got %+v", class, c, res.Flags)
			}
		}
	}
}

func TestSafeCapabilityNotFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{SourceType: "widget_t", TargetType: "widget_t", Class: "capability", Perms: []string{"net_bind_service"}}}
	if res := Refine(p, ds); len(res.Flags) != 0 {
		t.Errorf("net_bind_service is the one safe capability, must not be flagged: %+v", res.Flags)
	}
}
