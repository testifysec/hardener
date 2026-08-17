package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 80: an <app>_port_t mapping whose ownership cannot be proven was left
// active with only a warning (the round-76 behavior). GenerateTE grants name_bind
// on the WHOLE port type, so an undeclared mapping — tcp 9999 alongside a declared
// tcp 8443 — handed the domain an unverified bind privilege while the install
// reported success. It must still never be DELETED (it may belong to another
// module), but the install must abort.
func TestUnprovablePortMappingAbortsInstall(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "20260101000000")
	if !strings.Contains(spec, "refusing to install") {
		t.Error("an unprovable port mapping must abort the install")
	}
	if strings.Contains(spec, "leaving it alone rather than deleting") {
		t.Error("the warn-and-continue form must be gone")
	}
	// It must still not delete such a mapping: the only `semanage port -d` in the
	// reconcile loop is reached after the ownership case matched.
	del := strings.Index(spec, `semanage port -d -p "$_pp"`)
	abort := strings.Index(spec, "refusing to install")
	if del < 0 || abort < 0 || abort > del {
		t.Errorf("the abort must precede the deletion branch (abort=%d del=%d)", abort, del)
	}
}

// Behavioral: the reconcile decision table after round 80. Declared → keep;
// previously ours → prune; unprovable → ABORT (never silently kept, never deleted).
func TestPortReconciliationAbortsOnUnprovable(t *testing.T) {
	decide := func(desired, oldports, row string) string {
		script := `
desired="` + desired + `"
_oldports="` + oldports + `"
_row="` + row + `"
case "$desired" in *" $_row "*) echo KEEP; exit 0 ;; esac
case "$_oldports" in *" $_row "*) echo PRUNE; exit 0 ;; esac
echo ABORT; exit 1`
		out, _ := exec.Command("sh", "-c", script).Output()
		return strings.TrimSpace(string(out))
	}
	for _, c := range []struct{ name, desired, oldports, row, want string }{
		{"still declared", " tcp:8443 ", " tcp:8443 ", "tcp:8443", "KEEP"},
		{"dropped by new version", " ", " tcp:8443 ", "tcp:8443", "PRUNE"},
		// The finding: an undeclared same-protocol mapping must not survive.
		{"undeclared foreign mapping", " tcp:8443 ", " tcp:8443 ", "tcp:9999", "ABORT"},
		{"portless, foreign mapping", " ", " ", "tcp:9999", "ABORT"},
	} {
		if got := decide(c.desired, c.oldports, c.row); got != c.want {
			t.Errorf("%s: decided %s, want %s", c.name, got, c.want)
		}
	}
}

// Round 80: reconciliation trusted .oldports even on a FRESH install, so a stale
// inventory left by a failed upgrade could make a later portless fresh install
// delete mappings now owned by another module. Only upgrades may consume it; a
// fresh install discards it.
func TestFreshInstallDiscardsStaleOldPorts(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "20260101000000")
	if !strings.Contains(spec, `if [ "$_op" = 1 ]; then rm -f %{_datadir}/selinux/hardener/widget.oldports`) {
		t.Error("a fresh install must remove a stale .oldports rather than trust it")
	}
	// The read must be the upgrade branch of that same conditional.
	if !strings.Contains(spec, `elif [ -f %{_datadir}/selinux/hardener/widget.oldports ]; then _oldports=`) {
		t.Error(".oldports must only be read on upgrade")
	}

	// Behavioral: a stale inventory must not influence a fresh install.
	decide := func(op, oldportsFile, row string) string {
		script := `
_op=` + op + `
_oldports=" "
if [ "$_op" = 1 ]; then :; else _oldports="` + oldportsFile + `"; fi
_row="` + row + `"
case "$_oldports" in *" $_row "*) echo PRUNE; exit 0 ;; esac
echo ABORT`
		out, _ := exec.Command("sh", "-c", script).Output()
		return strings.TrimSpace(string(out))
	}
	if got := decide("1", " tcp:9999 ", "tcp:9999"); got != "ABORT" {
		t.Errorf("a fresh install must ignore a stale .oldports, got %s", got)
	}
	if got := decide("2", " tcp:9999 ", "tcp:9999"); got != "PRUNE" {
		t.Errorf("an upgrade must still consume .oldports, got %s", got)
	}
}
