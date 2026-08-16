package policy

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/avc"
)

// A denial whose target path falls under one of our own file-context mappings
// but carries a generic label is a LABELING problem, not a missing rule.
// audit2allow would emit `allow widget_t var_lib_t:file write` here — wrong.
func TestRefineDetectsMislabel(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "var_lib_t", Class: "file",
		Perms: []string{"write"}, Path: "/var/lib/widget/state.db",
	}}
	res := Refine(p, ds)
	if len(res.Relabels) != 1 {
		t.Fatalf("want 1 relabel, got %+v", res)
	}
	if len(res.AllowRules) != 0 {
		t.Errorf("mislabel must not produce an allow rule, got %v", res.AllowRules)
	}
	if res.Relabels[0].Path != "/var/lib/widget/state.db" {
		t.Errorf("relabel path: %q", res.Relabels[0].Path)
	}
	if res.Relabels[0].ExpectedType != "widget_var_lib_t" {
		t.Errorf("expected type: %q", res.Relabels[0].ExpectedType)
	}
}

// A denial against a foreign type with no path claim of ours is a genuine
// missing permission and becomes an allow rule.
func TestRefineEmitsAllowRule(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "net_conf_t", Class: "file",
		Perms: []string{"read", "open"}, Path: "/etc/resolv.conf",
	}}
	res := Refine(p, ds)
	if len(res.AllowRules) != 1 {
		t.Fatalf("want 1 allow rule, got %+v", res)
	}
	r := res.AllowRules[0]
	if r.Source != "widget_t" || r.Target != "net_conf_t" || r.Class != "file" {
		t.Errorf("rule: %+v", r)
	}
	if r.Render() != "allow widget_t net_conf_t:file { open read };" {
		t.Errorf("render: %q", r.Render())
	}
}

// Dangerous permissions survive into the output but are flagged for human review.
func TestRefineFlagsDangerous(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{
		{SourceType: "widget_t", TargetType: "widget_t", Class: "capability", Perms: []string{"sys_admin"}},
		{SourceType: "widget_t", TargetType: "shadow_t", Class: "file", Perms: []string{"read"}},
	}
	res := Refine(p, ds)
	if len(res.Flags) != 2 {
		t.Fatalf("want 2 flags, got %+v", res.Flags)
	}
}

// Denials from other domains (noise from the rest of the system) are ignored.
func TestRefineIgnoresForeignSource(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "sshd_t", TargetType: "etc_t", Class: "file", Perms: []string{"read"},
	}}
	res := Refine(p, ds)
	if len(res.AllowRules)+len(res.Relabels) != 0 {
		t.Errorf("foreign-source denial must be ignored, got %+v", res)
	}
}

// Executing a helper binary needs the full canonical read+exec permission
// set. Granting only the perms from one denial produces "perm creep": each
// verification run reveals exactly one more permission (getattr → read →
// open → map) and convergence takes a round per permission.
func TestExecHelperGetsCanonicalPermSet(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "hostname_exec_t", Class: "file",
		Perms: []string{"execute"}, Path: "/usr/bin/hostname",
	}}
	res := Refine(p, ds)
	if len(res.AllowRules) != 1 {
		t.Fatalf("want 1 rule, got %+v", res)
	}
	// Check the permission SET, not the rendered string: strings.Contains(got,
	// "execute") also matches "execute_no_trans", so a missing standalone
	// "execute" would slip through (review finding).
	permSet := map[string]bool{}
	for _, p := range res.AllowRules[0].Perms {
		permSet[p] = true
	}
	for _, perm := range []string{"execute", "execute_no_trans", "getattr", "map", "open", "read"} {
		if !permSet[perm] {
			t.Errorf("canonical exec set missing %q: %v", perm, res.AllowRules[0].Perms)
		}
	}
}

func TestRenderRefinement(t *testing.T) {
	rules := []AllowRule{
		{Source: "widget_t", Target: "cert_t", Class: "file", Perms: []string{"read", "open"}},
	}
	out := RenderRules(rules)
	if !strings.Contains(out, "allow widget_t cert_t:file { open read };") {
		t.Errorf("rendered:\n%s", out)
	}
}
