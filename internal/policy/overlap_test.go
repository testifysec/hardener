package policy

import (
	"testing"

	"github.com/testifysec/hardener/internal/avc"
	"github.com/testifysec/hardener/internal/profile"
)

// An executable path also matches the app's broad content claim. The EXACT
// executable matcher must win, or the correctly-labeled _exec_t helper is
// misread as relabel drift and its denial discarded (round-3 regression: I
// added pre-merge classification that trusts expectedType's first match).
func TestExactExecutableMatcherWins(t *testing.T) {
	p := &profile.Profile{
		Name:        "plex",
		Executables: []string{"/usr/lib/plexmediaserver/Plex Media Server"},
		Paths:       []profile.PathAccess{{Path: "/usr/lib/plexmediaserver(/.*)?", Kind: "content"}},
	}
	ms := compileFCMatchers(p)
	got, ok := expectedType(ms, "/usr/lib/plexmediaserver/Plex Media Server", "file")
	if !ok || got != "plex_exec_t" {
		t.Errorf("executable must resolve to plex_exec_t, got %q (ok=%v)", got, ok)
	}
	// A non-executable file under the same tree still resolves to content.
	if g, _ := expectedType(ms, "/usr/lib/plexmediaserver/Resources/lib.so", "file"); g != "plex_content_t" {
		t.Errorf("content file should resolve to plex_content_t, got %q", g)
	}

	// End to end: a denial on the correctly-labeled exec must NOT become a relabel.
	ds := []avc.Denial{{
		SourceType: "plex_t", TargetType: "plex_exec_t", Class: "file",
		Perms: []string{"read"}, Path: "/usr/lib/plexmediaserver/Plex Media Server",
	}}
	res := Refine(p, ds)
	if len(res.Relabels) != 0 {
		t.Errorf("correctly-labeled exec must not be flagged as relabel drift: %+v", res.Relabels)
	}
}

// User-namespace capability classes carry the same dangerous permissions and
// must go through review (webmin ships cap_userns sys_ptrace).
func TestUsernsCapabilityClassesFlagged(t *testing.T) {
	p := widgetProfile()
	for _, class := range []string{"cap_userns", "cap2_userns"} {
		ds := []avc.Denial{{
			SourceType: "widget_t", TargetType: "widget_t", Class: class, Perms: []string{"sys_ptrace"},
		}}
		res := Refine(p, ds)
		if len(res.Flags) != 1 {
			t.Errorf("class %s: sys_ptrace must be flagged, got %+v", class, res.Flags)
		}
	}
}
