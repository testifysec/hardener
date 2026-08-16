package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
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

// Round 20 (#5): rollback removes ONLY ports this transaction added (tracked in
// _added), never a pre-existing mapping owned by another service.
func TestSpecRollbackOnlyRemovesAddedPorts(t *testing.T) {
	p := &profile.Profile{Name: "widget", Ports: []profile.Port{{Proto: "tcp", Port: 8443}}}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, "for _row in $_added;") {
		t.Errorf("rollback must remove only ports tracked in _added:\n%s", spec)
	}
	if !strings.Contains(spec, `then _added="$_added tcp:8443"`) {
		t.Errorf("added ports must be recorded on success:\n%s", spec)
	}
}

// Round 20 (#6): an upgrade must prune <app>_port_t mappings no longer in the
// profile — a stale mapping would keep undeclared bind privilege.
func TestSpecPrunesStalePorts(t *testing.T) {
	p := &profile.Profile{Name: "widget", Ports: []profile.Port{{Proto: "tcp", Port: 8443}}}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, `case " tcp:8443 " in`) || !strings.Contains(spec, "could not prune stale port") {
		t.Errorf("spec must reconcile/prune stale port mappings:\n%s", spec)
	}
}
