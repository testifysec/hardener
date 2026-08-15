package policy

import (
	"testing"

	"github.com/testifysec/hardener/internal/avc"
)

// systemd (init_t) must be able to execute the unit's ExecStart binary to
// perform the domain transition. If we label that binary as plain content,
// init_t is denied execute and the service can NEVER start — while the
// confined domain itself produces zero denials, because it never runs.
// Reporting that as "0 denials" is the worst possible failure mode.
func TestRefineDetectsBrokenEntrypoint(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "init_t", TargetType: "widget_content_t", Class: "file",
		Perms: []string{"execute"}, Name: "widgetd",
	}}
	res := Refine(p, ds)
	if len(res.Entrypoints) != 1 {
		t.Fatalf("want 1 entrypoint issue, got %+v", res)
	}
	e := res.Entrypoints[0]
	if e.Name != "widgetd" || e.ObservedType != "widget_content_t" {
		t.Errorf("entrypoint issue: %+v", e)
	}
	// It must NOT become an allow rule — granting init_t execute on our content
	// type is the wrong fix; the binary needs the exec type instead.
	if len(res.AllowRules) != 0 {
		t.Errorf("must not emit an allow rule, got %v", res.AllowRules)
	}
}

// Denials from foreign domains against types that are not ours stay ignored.
func TestRefineStillIgnoresUnrelatedForeignDenials(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "sshd_t", TargetType: "etc_t", Class: "file", Perms: []string{"read"},
	}}
	res := Refine(p, ds)
	if len(res.AllowRules)+len(res.Relabels)+len(res.Entrypoints) != 0 {
		t.Errorf("unrelated denial must be ignored, got %+v", res)
	}
}

func TestOwnsType(t *testing.T) {
	p := widgetProfile()
	own := ownTypes(p)
	for _, yes := range []string{"widget_t", "widget_exec_t", "widget_conf_t", "widget_content_t"} {
		if !own[yes] {
			t.Errorf("%s should be recognized as ours", yes)
		}
	}
	for _, no := range []string{"init_t", "var_lib_t", "bin_t"} {
		if own[no] {
			t.Errorf("%s should NOT be ours", no)
		}
	}
}

// Entrypoint-mislabel detection must fire ONLY for the unit launcher (init_t)
// executing a NON-exec owned type (the mislabel case: entrypoint got
// content_t instead of _exec_t). It must not fire for unrelated foreign
// domains, nor for correctly-labeled _exec_t files (review finding).
func TestEntrypointDetectionIsScoped(t *testing.T) {
	p := widgetProfile()

	// Real mislabel: init_t denied execute on our content type → entrypoint issue.
	pos := Refine(p, []avc.Denial{{
		SourceType: "init_t", TargetType: "widget_content_t", Class: "file",
		Perms: []string{"execute"}, Name: "widgetd",
	}})
	if len(pos.Entrypoints) != 1 {
		t.Errorf("init_t exec on owned content must be an entrypoint issue: %+v", pos)
	}

	// Negatives — none of these is a mislabel:
	for _, d := range []avc.Denial{
		{SourceType: "sshd_t", TargetType: "widget_exec_t", Class: "file", Perms: []string{"execute"}},
		{SourceType: "sshd_t", TargetType: "widget_content_t", Class: "file", Perms: []string{"execute"}},
		{SourceType: "init_t", TargetType: "widget_exec_t", Class: "file", Perms: []string{"execute"}},
	} {
		if res := Refine(p, []avc.Denial{d}); len(res.Entrypoints) != 0 {
			t.Errorf("%s→%s must NOT be an entrypoint issue: %+v", d.SourceType, d.TargetType, res.Entrypoints)
		}
	}
}
