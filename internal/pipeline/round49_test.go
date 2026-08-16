package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// %post must verify DESCENDANT labels, not just each declared root: a more-
// specific base-policy file_contexts rule beneath a broad root retains a
// different, broader label while the root itself verifies correctly. The check
// mirrors the verifier-side installPolicy: a pruned `find ... ! -context ...
// -print -quit`. (review finding — round 49)
func TestSpecPostVerifiesDescendantLabels(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	spec := GenerateSpec(p, "20260101000000")

	for _, want := range []string{
		`! -context '*:widget_var_lib_t:*'`,
		"-print -quit",
		"is not labeled widget_var_lib_t",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("%%post missing descendant-label verification %q", want)
		}
	}
}

// The local file-context OVERLAP check must run REGARDLESS of whether the root
// exists yet — a rule under a not-yet-created data dir would mislabel the files
// the app creates on first run. So the `semanage fcontext -C -l` enumeration
// must appear BEFORE the `if [ -e "$_r" ]` existence guard, not inside it.
// (review finding — round 49)
func TestSpecPostOverlapCheckRunsRegardlessOfExistence(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	spec := GenerateSpec(p, "20260101000000")

	overlap := strings.Index(spec, "could not enumerate local file-contexts")
	guard := strings.Index(spec, `if [ -e "$_r" ]`)
	if overlap < 0 || guard < 0 {
		t.Fatalf("expected both the overlap check and the existence guard in %%post (overlap=%d guard=%d)", overlap, guard)
	}
	if overlap > guard {
		t.Errorf("overlap check must run before the existence guard, not inside it (overlap=%d guard=%d)", overlap, guard)
	}
}

// The descendant scan prunes any OTHER declared sub-root under a broad root, so
// a legitimately-overlapping declared path (its own app type) is not flagged.
func TestSpecPostDescendantScanPrunesDeclaredSubRoots(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths: []profile.PathAccess{
			{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"},
			{Path: "/var/lib/widget/conf(/.*)?", Kind: "conf"},
		},
	}
	spec := GenerateSpec(p, "20260101000000")
	if !strings.Contains(spec, "-path '/var/lib/widget/conf' -prune -o") {
		t.Errorf("descendant scan of the broad root must prune the declared conf sub-root:\n%s", spec)
	}
}
