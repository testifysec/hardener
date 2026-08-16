package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 74: both module-removal verifications captured `semodule -l` output but
// discarded its EXIT STATUS, testing only for emptiness. A semodule that fails
// partway can exit nonzero having already printed some modules; that partial list
// will not contain ours, which reads as "removed" — so an uninstall restores base
// labels (or a rollback reports success) while the policy module is still loaded.
// Both sites must capture the status and fail on any nonzero.
func TestModuleRemovalChecksCaptureExitStatus(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "20260101000000")
	for _, want := range []string{
		`_ml="$(semodule -l 2>/dev/null)" || _mlrc=$?`,   // %post rollback
		`_mlu="$(semodule -l 2>/dev/null)" || _mlurc=$?`, // %postun
		`[ "$_mlrc" != 0 ] || [ -z "$_ml" ]`,
		`[ "$_mlurc" != 0 ] || [ -z "$_mlu" ]`,
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("module-removal check must capture the exit status; missing %q", want)
		}
	}
	// The old status-discarding forms must be gone.
	for _, gone := range []string{
		"_ml=\"$(semodule -l 2>/dev/null)\"\n        if [ -z \"$_ml\" ]",
		"_mlu=\"$(semodule -l 2>/dev/null)\"\n    if [ -z \"$_mlu\" ]",
	} {
		if strings.Contains(spec, gone) {
			t.Errorf("a status-discarding module check survives: %q", gone)
		}
	}
}

// Behavioral: the emitted guard must treat PARTIAL output with a nonzero exit as
// unverifiable, while still distinguishing a genuine "removed" from "still
// present" on a clean enumeration.
func TestModuleRemovalGuardBehavior(t *testing.T) {
	// PRODUCER is substituted per case; the shell's own printf format stays literal
	// (this is a plain string replace, not a fmt template).
	guard := `_mlurc=0
_mlu="$(PRODUCER)" || _mlurc=$?
if [ "$_mlurc" != 0 ] || [ -z "$_mlu" ]; then echo FAILCLOSED; exit 0; fi
if printf '%s\n' "$_mlu" | grep -qE "^widget([[:space:]]|$)"; then echo STILL-PRESENT; else echo REMOVED; fi`

	for _, c := range []struct {
		name, producer, want string
	}{
		// The exact scenario in the finding: semodule dies partway, our module is
		// absent from the partial list. Must NOT read as removed.
		{"partial output, nonzero exit", `printf "base\nselinux-policy\n"; exit 1`, "FAILCLOSED"},
		{"empty output", `true`, "FAILCLOSED"},
		{"clean list without ours", `printf "base\nselinux-policy\nunconfined\n"`, "REMOVED"},
		{"clean list with ours", `printf "base\nwidget\n"`, "STILL-PRESENT"},
		// Tab-delimited form (older semodule prints "name\tversion").
		{"tab-delimited, ours present", `printf "base\twidget\nwidget\t1.0\n"`, "STILL-PRESENT"},
	} {
		out, err := exec.Command("sh", "-c", strings.Replace(guard, "PRODUCER", c.producer, 1)).Output()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := strings.TrimSpace(string(out)); got != c.want {
			t.Errorf("%s: guard said %q, want %q", c.name, got, c.want)
		}
	}
}
