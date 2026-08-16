package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 76: upgrade reconciliation assumed every <app>_port_t mapping belonged to
// the previous package. A PORTLESS profile never declares that type, so a foreign
// module can legitimately own it — and on upgrade the fresh-install ownership
// check is skipped, so unconditional pruning deleted the foreign mappings. A
// successful upgrade sets _ok=1, so rollback never restored them. Each build now
// ships its declared proto:port set as <app>.ports, %pre stashes it to .oldports,
// and a row is pruned only if it appears there.
func TestPortlessUpgradeDoesNotPruneForeignMappings(t *testing.T) {
	portless := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		// no Ports at all
	}
	spec := GenerateSpec(portless, "20260101000000")

	// Reconciliation must consult the previous package's declared port inventory.
	for _, want := range []string{
		"widget.oldports",
		"was not declared by the previous widget package",
		"leaving it alone rather than deleting",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("reconciliation must verify prior port ownership; missing %q", want)
		}
	}
	// The inventory must be shipped, stashed like .roots, and packaged.
	if !strings.Contains(spec, "cat > %{buildroot}%{_datadir}/selinux/hardener/widget.ports") {
		t.Error("the build must ship a widget.ports inventory")
	}
	if !strings.Contains(spec, "cp %{_datadir}/selinux/hardener/widget.ports %{_datadir}/selinux/hardener/widget.oldports") {
		t.Error("pre scriptlet must stash the previous port inventory on upgrade")
	}
	files := spec[strings.Index(spec, "\n%files\n"):]
	if !strings.Contains(files, "%{_datadir}/selinux/hardener/widget.ports") {
		t.Error("the ports inventory must be packaged, or rpmbuild fails on an unpackaged file")
	}
}

// Behavioral: the reconciliation decision table. A row still declared is kept; a
// row the PREVIOUS package declared but the new one dropped is pruned; a row that
// was never ours is left alone (never deleted).
func TestPortReconciliationOwnershipDecisions(t *testing.T) {
	// Mirrors the emitted shell: desired = new declared set, oldports = previous.
	decide := func(desired, oldports, row string) string {
		script := `
desired="` + desired + `"
_oldports="` + oldports + `"
_row="` + row + `"
case "$desired" in *" $_row "*) echo KEEP; exit 0 ;; esac
case "$_oldports" in *" $_row "*) echo PRUNE; exit 0 ;; esac
echo LEAVE`
		out, err := exec.Command("sh", "-c", script).Output()
		if err != nil {
			t.Fatalf("shell: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	cases := []struct{ name, desired, oldports, row, want string }{
		{"still declared", " tcp:8443 ", " tcp:8443 ", "tcp:8443", "KEEP"},
		{"dropped by new version", " ", " tcp:8443 ", "tcp:8443", "PRUNE"},
		// The finding: portless profile, foreign module owns <app>_port_t.
		{"portless, foreign mapping", " ", " ", "tcp:9999", "LEAVE"},
		{"portless, previously ours", " ", " tcp:9999 ", "tcp:9999", "PRUNE"},
		{"changed port, old pruned", " tcp:8444 ", " tcp:8443 ", "tcp:8443", "PRUNE"},
	}
	for _, c := range cases {
		if got := decide(c.desired, c.oldports, c.row); got != c.want {
			t.Errorf("%s: decided %s, want %s", c.name, got, c.want)
		}
	}
}
