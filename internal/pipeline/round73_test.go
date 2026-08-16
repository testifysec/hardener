package pipeline

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

func spec73(t *testing.T) (spec, pre, post string) {
	t.Helper()
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	spec = GenerateSpec(p, "20260101000000")
	pre = spec[strings.Index(spec, "\n%pre\n"):]
	pre = pre[:strings.Index(pre, "\n%post\n")]
	post = spec[strings.Index(spec, "\n%post\n"):]
	post = post[:strings.Index(post, "\n%postun\n")]
	return
}

// Round 73: read-only validation (hard-linked entrypoints/descendants, local
// file-context conflicts) ran ONLY in %post — after rpm commits the payload and
// NEVRA. Failing there rolls back the module but leaves the package recorded as
// installed, so retrying the same NEVRA is a no-op and the host can be left
// without the intended confinement. The same checks must run in %pre, where a
// failure aborts the transaction cleanly, and remain in %post as a recheck.
func TestReadOnlyValidationRunsInPreAndPost(t *testing.T) {
	_, pre, post := spec73(t)
	for _, want := range []string{
		"hard-link count",                 // entrypoint link validation
		"is a hard link (link count > 1)", // descendant link validation
		"overlaps declared root",          // local file-context conflict
	} {
		if !strings.Contains(pre, want) {
			t.Errorf("pre scriptlet missing read-only validation %q", want)
		}
		if !strings.Contains(post, want) {
			t.Errorf("post scriptlet must still recheck %q", want)
		}
	}
	// %pre stays read-only: no relabeling or module loading before the commit.
	var code strings.Builder
	for _, ln := range strings.Split(pre, "\n") {
		if s := strings.TrimSpace(ln); s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		code.WriteString(ln + "\n")
	}
	for _, forbidden := range []string{"restorecon -RF", "restorecon -F", "semodule -i", "semanage port -a"} {
		if strings.Contains(code.String(), forbidden) {
			t.Errorf("pre scriptlet must not mutate state (found %q)", forbidden)
		}
	}
	// The recheck must precede the actual relabel pass. Anchor on the mutation
	// block's own error text — an earlier `restorecon -RF` also appears inside the
	// _rollback function definition, which is not the mutation being guarded.
	chk := strings.Index(post, "is a hard link (link count > 1)")
	mut := strings.Index(post, "could not relabel declared root")
	if chk < 0 || mut < 0 || chk > mut {
		t.Errorf("post scriptlet must recheck before relabeling (chk=%d mut=%d)", chk, mut)
	}
}

// Round 73: `restorecon -RF` relabels by INODE, so a multi-link regular file under
// a declared root retypes every alias — including aliases OUTSIDE the root, which
// with a writable app type hands the confined service access to an unrelated file.
// Entrypoints were already held to this standard; descendants now are too.
// Behavioral: run the real find(1) expression against a tree with and without a
// hard-linked descendant. (Also verified on the verifier VM.)
func TestDescendantHardLinkDetection(t *testing.T) {
	dir := t.TempDir()
	script := func(body string) *exec.Cmd { return exec.Command("sh", "-c", body) }

	setup := "set -e; mkdir -p " + dir + "/root/sub " + dir + "/outside; " +
		"echo a > " + dir + "/root/normal.txt; echo b > " + dir + "/outside/orig.txt; "
	find := `_hl=$(find ` + dir + `/root ! -type d -links +1 -print -quit 2>/dev/null); [ -n "$_hl" ]`

	// A: a hard link from outside INTO the declared root must be detected.
	if err := script(setup + "ln " + dir + "/outside/orig.txt " + dir + "/root/alias.txt; " + find).Run(); err != nil {
		t.Error("a hard-linked descendant must be detected")
	}
	// B: a clean tree must NOT trigger (no false positive), including directories,
	// whose link counts are always > 1 because of subdirectories.
	if err := script("rm -f " + dir + "/root/alias.txt; " + find).Run(); err == nil {
		t.Error("a tree with no hard-linked regular files must not trigger the check")
	}
}

// The spec must prune legitimately-overlapping declared sub-roots from the
// hard-link scan, exactly as the descendant LABEL check does — otherwise a
// declared sub-root would be walked twice under two different roots.
func TestHardLinkScanPrunesDeclaredSubRoots(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths: []profile.PathAccess{
			{Path: "/opt/widget(/.*)?", Kind: "content"},
			{Path: "/opt/widget/var(/.*)?", Kind: "var_lib"},
		},
	}
	spec := GenerateSpec(p, "20260101000000")
	if !strings.Contains(spec, `-path '/opt/widget/var' -prune -o ! -type d -links +1`) {
		t.Error("the hard-link scan must prune declared sub-roots the same way the label check does")
	}
}
