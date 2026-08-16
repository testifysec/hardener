package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/target"
)

// Round 65: a privileged/untrusted exercise can `auditctl -e 0`, do denial-worthy
// work, then `auditctl -e 1`. Both the before- and after-snapshots then read
// enabled=1 and the lost counter never moves, so those checks pass while AVCs were
// suppressed. The kernel logs a CONFIG_CHANGE audit_enabled record for the toggle,
// and it lands in the sentinel-bounded window; exercise() must fail closed on it.
func TestExerciseFailsClosedOnAuditToggleInWindow(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{
		responses: map[string]string{
			"stat -c '%s %i'":           "100 4242",
			"stat -c '%s'":              "100",
			"stat -c '%i'":              "4242",
			"auditctl -s":               "enabled 1 lost 0 backlog 0", // reads clean before AND after
			"grep -Fc":                  "1",
			"is-active widget.service":  "inactive",
			"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
			// The audit window carries the re-enable CONFIG_CHANGE the toggle emitted.
			"tail -c": "type=CONFIG_CHANGE msg=audit(1700000000.123:42): op=set audit_enabled=1 old=0 auid=0 ses=1 res=1",
		},
	}
	_, _, _, err := exercise(f, tgt, "widget_t")
	if err == nil || !strings.Contains(err.Error(), "reconfigured during the exercise") {
		t.Fatalf("an audit_enabled toggle in the window must fail closed, got %v", err)
	}
}

// Round 65: the disable-and-leave-off variant — a workload runs `auditctl -e 0`
// and never re-enables. The after-snapshot then reads enabled=0; exercise() must
// fail closed rather than trust a zero-denial result from an unaudited window.
func TestExerciseFailsClosedWhenAuditingLeftDisabledAfter(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{
		responses: map[string]string{
			"stat -c '%s %i'":           "100 4242",
			"stat -c '%s'":              "100",
			"stat -c '%i'":              "4242",
			"grep -Fc":                  "1",
			"is-active widget.service":  "inactive",
			"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
		},
		seq: map[string][]string{
			// enabled before the exercise, disabled (and left off) after it.
			"auditctl -s": {"enabled 1 lost 0 backlog 0", "enabled 0 lost 0 backlog 0"},
		},
	}
	_, _, _, err := exercise(f, tgt, "widget_t")
	if err == nil || !strings.Contains(err.Error(), "auditing was disabled during the exercise") {
		t.Fatalf("auditing left disabled after the exercise must fail closed, got %v", err)
	}
}
