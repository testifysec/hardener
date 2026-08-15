package policy

import (
	"testing"

	"github.com/testifysec/hardener/internal/avc"
)

// Executable-memory permissions on the process class are high-impact (they
// defeat W^X) and must go to review. They are not capability-class, so the
// capability-only check missed them (Emby/Splunk shipped execmem unreviewed).
func TestProcessExecMemFlagged(t *testing.T) {
	p := widgetProfile()
	for _, perm := range []string{"execmem", "execstack", "execheap"} {
		ds := []avc.Denial{{
			SourceType: "widget_t", TargetType: "widget_t", Class: "process", Perms: []string{perm},
		}}
		res := Refine(p, ds)
		if len(res.Flags) != 1 {
			t.Errorf("process:%s must be flagged, got %+v", perm, res.Flags)
		}
	}
}

// ptrace on the process class is also review-worthy.
func TestProcessPtraceFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "sysadm_t", Class: "process", Perms: []string{"ptrace"},
	}}
	if res := Refine(p, ds); len(res.Flags) != 1 {
		t.Errorf("process:ptrace must be flagged, got %+v", res.Flags)
	}
}

// Ordinary process perms (signal, fork) are not flagged.
func TestOrdinaryProcessPermsNotFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "widget_t", Class: "process", Perms: []string{"signal", "getsched"},
	}}
	if res := Refine(p, ds); len(res.Flags) != 0 {
		t.Errorf("ordinary process perms must not be flagged, got %+v", res.Flags)
	}
}
