package pipeline

import (
	"strings"
	"testing"
)

// Round 20 (#3): a rule discovered in the observe loop must be present in the
// FINAL installed policy before enforcement — not lost between the last observe
// round and the enforce phase.
func TestFinalPolicyInstalledBeforeEnforce(t *testing.T) {
	f := passingRunner()
	f.responses["tail -c"] = `type=AVC msg=audit(1.2:3): avc:  denied  { read } for  pid=1 comm="widgetd" scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:httpd_sys_content_t:s0 tclass=file permissive=1`
	res := Run(f, testTarget(), Options{MaxRounds: 3, AcceptFlagged: true})
	if !strings.Contains(res.FinalTE, "httpd_sys_content_t") {
		t.Errorf("the refined rule must be in the final installed policy:\n%s", res.FinalTE)
	}
}
