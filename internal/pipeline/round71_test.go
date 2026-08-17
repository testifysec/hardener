package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/target"
)

// Round 71: the audit write-barrier token used to embed the start inode and byte
// offset — both stat-able by a root exercise — and the window is cut at the FIRST
// occurrence. The exercise could therefore derive the token, write it into
// audit.log BEFORE doing denial-worthy work, and every later AVC (and every
// tampering record) would be parsed off the end of the window. The token must be
// an unguessable nonce, and it must appear exactly once.
func TestAuditBarrierTokenIsUnpredictable(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	newFake := func() *fakeRunner {
		return &fakeRunner{responses: map[string]string{
			"stat -c '%s %i'":           "100 4242",
			"stat -c '%s'":              "100",
			"stat -c '%i'":              "4242",
			"auditctl -s":               "enabled 1 lost 0 backlog 0",
			"grep -Fc":                  "1",
			"is-active widget.service":  "inactive",
			"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
		}}
	}
	tokenOf := func(f *fakeRunner) string {
		for _, c := range f.calls {
			if strings.Contains(c, "auditctl -m") && strings.Contains(c, "hardener-barrier-") {
				return c
			}
		}
		return ""
	}
	f1, f2 := newFake(), newFake()
	if _, _, _, err := exercise(f1, tgt, "widget_t"); err != nil {
		t.Fatalf("exercise 1: %v", err)
	}
	if _, _, _, err := exercise(f2, tgt, "widget_t"); err != nil {
		t.Fatalf("exercise 2: %v", err)
	}
	t1, t2 := tokenOf(f1), tokenOf(f2)
	if t1 == "" || t2 == "" {
		t.Fatal("no barrier sentinel was emitted")
	}
	// Two runs with IDENTICAL stat output (same inode, same offset) must still
	// produce different tokens — proving the token is not derived from guest state.
	if t1 == t2 {
		t.Errorf("barrier token is predictable: identical across runs with identical stat output (%q)", t1)
	}
	// And it must not contain the inode/offset the guest can read.
	if strings.Contains(t1, "4242") || strings.Contains(t1, "-100") {
		t.Errorf("barrier token embeds guest-readable state (inode/offset): %q", t1)
	}
}

// Round 71: a replayed boundary token must fail closed. Cutting at the first
// occurrence when two are present would silently discard everything between them.
func TestAuditBarrierRejectsReplayedToken(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{responses: map[string]string{
		"stat -c '%s %i'":           "100 4242",
		"stat -c '%s'":              "100",
		"stat -c '%i'":              "4242",
		"auditctl -s":               "enabled 1 lost 0 backlog 0",
		"grep -Fc":                  "1",
		"is-active widget.service":  "inactive",
		"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
	}}
	f.duplicateBarrier = true // the fake echoes the token twice
	_, _, _, err := exercise(f, tgt, "widget_t")
	if err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("a duplicated barrier token must fail closed, got %v", err)
	}
}
