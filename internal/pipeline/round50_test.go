package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// The %post overlap program (shell-level, after Go unescaping). Kept in sync
// with rpm.go by the Contains assertion below.
const overlapAwkProg = `$1 ~ /^\// { p=$1; if (length(p)>=6 && substr(p,length(p)-5)=="(/.*)?") p=substr(p,1,length(p)-6); while (length(p)>1 && substr(p,length(p),1)=="/") p=substr(p,1,length(p)-1); if (p=="") next; rp=r"/"; pp=p"/"; if (p==r || index(rp,pp)==1 || index(pp,rp)==1) { print p; exit } }`

// The %post local-fcontext overlap guard must reject a rule that EQUALS, is an
// ANCESTOR of, or is a DESCENDANT of a declared root — not descendants only.
// Run the real awk program against representative `semanage fcontext -C -l`
// listings to prove all three directions fire and non-overlaps don't. (round 50)
func TestPostOverlapAwkDetectsAllThreeDirections(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	spec := GenerateSpec(p, "20260101000000")
	if !strings.Contains(spec, overlapAwkProg) {
		t.Fatalf("generated %%post no longer contains the overlap awk program; update the test in lockstep")
	}

	cases := []struct {
		name    string
		fclist  string
		overlap bool
	}{
		{"exact-with-regex", "/var/lib/widget(/.*)?    system_u:object_r:some_t:s0", true},
		{"exact-bare", "/var/lib/widget    system_u:object_r:some_t:s0", true},
		{"ancestor", "/var/lib(/.*)?    system_u:object_r:some_t:s0", true},
		{"descendant", "/var/lib/widget/sub(/.*)?    system_u:object_r:some_t:s0", true},
		{"sibling-no-overlap", "/var/lib/other(/.*)?    system_u:object_r:some_t:s0", false},
		{"unrelated", "/etc/foo(/.*)?    system_u:object_r:some_t:s0", false},
		{"prefix-string-not-path", "/var/lib/widgetary(/.*)?    system_u:object_r:some_t:s0", false},
	}
	for _, c := range cases {
		cmd := exec.Command("awk", "-v", "r=/var/lib/widget", overlapAwkProg)
		cmd.Stdin = strings.NewReader(c.fclist + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: awk failed: %v", c.name, err)
		}
		got := strings.TrimSpace(string(out)) != ""
		if got != c.overlap {
			t.Errorf("%s (%q): overlap=%v want %v (awk output %q)", c.name, c.fclist, got, c.overlap, out)
		}
	}
}

// A target-loaded auxiliary SELinux module that appears AFTER the pre-exercise
// baseline must fail the run: such a module can grant what our policy doesn't
// and suppress the denials enforcement verification samples, faking a clean
// pass. recheck snapshots the module set and fails closed on any addition.
// (review finding — round 50)
func TestRecheckFailsOnUnexpectedModule(t *testing.T) {
	f := passingRunner()
	// seq wins over the static "semodule -l": clean baseline for the name-conflict
	// probes + the baseline capture, then an extra module by the time recheck runs.
	f.seq = map[string][]string{
		"semodule -l": {
			"base\nselinux-policy\nunconfined\n",             // nameConflict (pre-install)
			"base\nselinux-policy\nunconfined\n",             // nameConflict (post-install)
			"base\nselinux-policy\nunconfined\n",             // baseline capture
			"base\nselinux-policy\nunconfined\nevilhelper\n", // recheck → foreign module
		},
	}
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if !strings.Contains(res.FailureReason, "unexpected SELinux module") {
		t.Errorf("a foreign module loaded after baseline must fail the run, got %q", res.FailureReason)
	}
}
