package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// The fresh-install foreign-module conflict guard must match the module name
// followed by ANY whitespace, not a literal space. `semodule -l` prints
// "name\tversion" (tab) on older toolchains and a bare "name" on newer ones; a
// `( |$)` pattern misses the tab form, so the installer would fail to see a
// foreign same-name module, load ours over it, and a rollback (semodule -r)
// would delete unrelated policy. (review finding — round 48)
func TestSpecConflictGuardMatchesTabDelimitedModuleList(t *testing.T) {
	p := &profile.Profile{Name: "widget", Executables: []string{"/opt/widget/bin/widgetd"}}
	spec := GenerateSpec(p, "20260101000000")

	if strings.Contains(spec, `grep -qE "^widget( |$)"`) {
		t.Error("guard still uses the literal-space pattern; tab-delimited semodule -l entries slip through")
	}
	want := `grep -qE "^widget([[:space:]]|$)"`
	if !strings.Contains(spec, want) {
		t.Fatalf("spec missing whitespace-class conflict guard %q", want)
	}

	// Prove the pattern actually catches the tab-delimited form and stays
	// correctly anchored (a differently-named module must NOT match).
	pat := `^widget([[:space:]]|$)`
	cases := []struct {
		line string
		hit  bool
	}{
		{"widget\t1.0", true}, // older semodule: tab-delimited
		{"widget 1.0", true},  // space-delimited
		{"widget", true},      // newer semodule: bare name
		{"widgetary\t1.0", false},
		{"otherwidget\t1.0", false},
	}
	for _, c := range cases {
		// grep -qE returns 0 on match, 1 on no match.
		cmd := exec.Command("grep", "-qE", pat)
		cmd.Stdin = strings.NewReader(c.line + "\n")
		err := cmd.Run()
		matched := err == nil
		if matched != c.hit {
			t.Errorf("pattern %q against %q: matched=%v want %v", pat, c.line, matched, c.hit)
		}
	}
}
