package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
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

// Round 71 (error path): the upgrade snapshot must be taken in %pre, where a
// failure aborts the transaction BEFORE rpm commits the new payload and NEVRA.
// Taking it in %post left the old policy active with the new files already
// recorded as installed, and retrying the same NEVRA is a no-op.
func TestSpecSnapshotsUpgradeInPre(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	spec := GenerateSpec(p, "20260101000000")
	pre := spec[strings.Index(spec, "\n%pre\n"):]
	pre = pre[:strings.Index(pre, "\n%post\n")]
	post := spec[strings.Index(spec, "\n%post\n"):]
	post = post[:strings.Index(post, "\n%postun\n")]

	// %pre takes the snapshot and aborts the transaction if it cannot.
	for _, want := range []string{
		"semodule -E widget",
		"refusing a non-atomic upgrade",
		"widget.snap",
	} {
		if !strings.Contains(pre, want) {
			t.Errorf("pre scriptlet must snapshot the old module; missing %q", want)
		}
	}
	// %post must CONSUME that snapshot, never create its own with mktemp.
	// (%post still uses mktemp for the rollback VERIFY dir; what must be gone is
	// creating the SNAPSHOT there.)
	if strings.Contains(post, `_snap="$(mktemp`) {
		t.Error("post scriptlet must not create the upgrade snapshot itself — it runs after the commit")
	}
	if !strings.Contains(post, "_snap=%{_datadir}/selinux/hardener/widget.snap") {
		t.Error("post scriptlet must consume the snapshot taken in the pre scriptlet")
	}
	if !strings.Contains(post, "the pre-upgrade widget module snapshot is missing or empty") {
		t.Error("post scriptlet must fail closed when the pre-scriptlet snapshot is absent or empty")
	}
	// Behavioral: the emptiness guard fires on a missing dir and on an empty dir,
	// and passes on a populated one.
	guard := `if [ ! -d "$_snap" ] || [ -z "$(ls -A "$_snap" 2>/dev/null)" ]; then exit 1; fi`
	for _, c := range []struct {
		name  string
		setup string
		fail  bool
	}{
		{"missing", `_snap=/nonexistent/hardener-snap-test`, true},
		{"empty", `_snap=$(mktemp -d)`, true},
		{"populated", `_snap=$(mktemp -d); : > "$_snap/widget.cil"`, false},
	} {
		cmd := exec.Command("sh", "-c", c.setup+"\n"+guard)
		failed := cmd.Run() != nil
		if failed != c.fail {
			t.Errorf("snapshot guard (%s): failed=%v want %v", c.name, failed, c.fail)
		}
	}
}
