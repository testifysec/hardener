package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// buildRPM must compile the packaged .pp FRESH from the verified policy text
// (res.FinalTE/FinalFC) in a dedicated pkg dir, never copying the staged
// /tmp/hardener/<app>/<app>.pp — a root-privileged exercise could have swapped
// that staged file after enforcement, packaging unverified policy bytes while
// the loaded module stayed clean. (review finding — round 55)
func TestBuildRPMPackagesFreshlyCompiledVerifiedPolicy(t *testing.T) {
	f := passingRunner()
	p := &profile.Profile{Name: "widget", Executables: []string{"/opt/widget/bin/widgetd"}}
	verifiedTE := "policy_module(widget, 1.0.0)\ntype widget_t;\n"
	verifiedFC := "/opt/widget/bin/widgetd -- gen_context(system_u:object_r:widget_exec_t,s0)\n"
	if _, err := buildRPM(f, p, "20260101000000", verifiedTE, verifiedFC); err != nil {
		t.Fatalf("buildRPM: %v", err)
	}

	compiledFresh := false
	copiedStagedPP := false
	for _, c := range f.calls {
		if strings.Contains(c, "cd /tmp/hardener/widget/pkg") &&
			strings.Contains(c, "make -f /usr/share/selinux/devel/Makefile widget.pp") {
			compiledFresh = true
		}
		// The OLD behavior copied the staged (non-pkg) .pp directly.
		if strings.Contains(c, "cp /tmp/hardener/widget/widget.pp ") {
			copiedStagedPP = true
		}
	}
	if !compiledFresh {
		t.Error("buildRPM must recompile the .pp from verified text in the pkg dir")
	}
	if copiedStagedPP {
		t.Error("buildRPM must NOT copy the swappable staged /tmp/hardener/widget/widget.pp")
	}
}
