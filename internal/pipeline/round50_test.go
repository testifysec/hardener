package pipeline

import (
	"strings"
	"testing"
)

// The %post overlap program (shell-level, after Go unescaping). Kept in sync
// with rpm.go by the Contains assertion below.
const overlapAwkProg = `$1 ~ /^\// { p=$1; m=match(p, /[].^$*+?(){}|[\\]/); if (m>0) p=substr(p,1,m-1); while (length(p)>1 && substr(p,length(p),1)=="/") p=substr(p,1,length(p)-1); if (p=="") next; rp=r"/"; pp=p"/"; if (p==r || index(rp,pp)==1 || index(pp,rp)==1) { print p; exit } }`

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
