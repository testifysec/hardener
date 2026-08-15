package policy

import (
	"testing"

	"github.com/testifysec/hardener/internal/avc"
)

// Relabel classification must happen per-denial BEFORE merging: merging a
// mislabeled-path denial with a genuine foreign-access denial (same
// source/target/class) would otherwise erase the path evidence and emit a
// type-wide allow rule covering both.
func TestRelabelClassifiedBeforeMerge(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{
		// mislabel: path is under our var_lib claim but carries var_lib_t
		{SourceType: "widget_t", TargetType: "var_lib_t", Class: "file",
			Perms: []string{"write"}, Path: "/var/lib/widget/state.db"},
		// genuine: same target type/class, different (foreign) path
		{SourceType: "widget_t", TargetType: "var_lib_t", Class: "file",
			Perms: []string{"read"}, Path: "/var/lib/other-app/data"},
	}
	res := Refine(p, ds)
	if len(res.Relabels) != 1 || res.Relabels[0].Path != "/var/lib/widget/state.db" {
		t.Fatalf("mislabel lost in merge: %+v", res)
	}
	// The genuine denial hits a generic shared type → review flag, not silent rule.
	if len(res.Flags) != 1 {
		t.Fatalf("foreign generic-type access must be flagged: %+v", res)
	}
	for _, f := range res.Flags {
		for _, perm := range f.Rule.Perms {
			if perm == "write" {
				t.Errorf("mislabel's write perm leaked into the flagged rule: %+v", f.Rule)
			}
		}
	}
}

// Declared manifest capabilities go through the same danger gate as observed
// ones; they must not silently reach the TE nor vanish from conformance.
func TestDeclaredCapabilitiesAreFlagged(t *testing.T) {
	flags := FlagDeclaredCapabilities("widget", []string{"net_bind_service", "sys_admin"})
	if len(flags) != 1 {
		t.Fatalf("want exactly the dangerous capability flagged, got %+v", flags)
	}
	if flags[0].Rule.Perms[0] != "sys_admin" {
		t.Errorf("flag: %+v", flags[0])
	}
}
