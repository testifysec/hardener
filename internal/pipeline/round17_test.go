package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/vm"
)

// Round 17 (#2): the %post error messages must not interpolate the raw path.
// The path is bound to a shell variable from its single-quoted literal and
// every message references "$_e" — so $(...) in a manifest path can never
// execute as root when relabeling fails.
func TestSpecErrorMessagesDoNotExecutePaths(t *testing.T) {
	evil := "/opt/x/$(touch PWNED)"
	p := &profile.Profile{Name: "widget", Executables: []string{evil}}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, "_e="+vm.ShellQuote(evil)) {
		t.Errorf("path must be bound to a shell var from its quoted literal:\n%s", spec)
	}
	// The raw path must never sit right after a double quote (an executable
	// position). Its only occurrence is the single-quoted _e= assignment.
	if strings.Contains(spec, `"`+evil) {
		t.Errorf("raw path inside double quotes is injectable:\n%s", spec)
	}
	if !strings.Contains(spec, `printf 'ERROR: cannot label entrypoint %s`) {
		t.Errorf("diagnostics must use printf with a quoted arg:\n%s", spec)
	}
}

// Round 17 (#4b): port assignment must fail CLOSED — verify the port ends up
// under the app's type, never swallow the failure with `|| :` (which left the
// service binding an unintended port type).
func TestSpecPortAssignmentFailsClosed(t *testing.T) {
	p := &profile.Profile{Name: "widget", Ports: []profile.Port{{Proto: "tcp", Port: 8443}}}
	spec := GenerateSpec(p, "1")
	if strings.Contains(spec, "port -a -t widget_port_t -p tcp 8443 2>/dev/null || :") {
		t.Error("port ADD must not fail open with '|| :'")
	}
	if !strings.Contains(spec, "grep -qw 8443") || !strings.Contains(spec, "refusing to leave") {
		t.Errorf("port assignment must verify and fail closed:\n%s", spec)
	}
}
