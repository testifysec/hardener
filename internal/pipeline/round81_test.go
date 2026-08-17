package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 81: %pre invokes semanage (the fresh-install port-ownership guard and the
// local file-context overlap check) and semodule, but only Requires(post) and
// Requires(postun) were declared. A plain `Requires:` orders the package's runtime
// dependency, not this package's own scriptlets — RPM needs Requires(pre). On a
// minimal host %pre could therefore run before policycoreutils-python-utils was
// installed, and because the preflight fails CLOSED on an unusable semanage, the
// install is REFUSED rather than degraded.
func TestSpecDeclaresPreScriptletDependencies(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "20260101000000")
	if !strings.Contains(spec, "Requires(pre):  policycoreutils policycoreutils-python-utils") {
		t.Error("the spec must declare Requires(pre) for the tools the pre scriptlet invokes")
	}
	// Guard the invariant rather than the literal: every scriptlet-provided tool
	// used in %pre must be covered by a Requires(pre).
	pre := spec[strings.Index(spec, "\n%pre\n"):]
	pre = pre[:strings.Index(pre, "\n%post\n")]
	reqLine := ""
	for _, ln := range strings.Split(spec, "\n") {
		if strings.HasPrefix(ln, "Requires(pre):") {
			reqLine = ln
		}
	}
	if reqLine == "" {
		t.Fatal("no Requires(pre) line")
	}
	for tool, pkg := range map[string]string{
		"semanage": "policycoreutils-python-utils",
		"semodule": "policycoreutils",
	} {
		if strings.Contains(pre, tool+" ") && !strings.Contains(reqLine, pkg) {
			t.Errorf("the pre scriptlet uses %s but Requires(pre) does not include %s", tool, pkg)
		}
	}
}

// Round 81: the round-80 suffix rule catches the exact per-user systemd path
// (/srv/people/bob/.config/systemd/user) but NOT its ancestor
// (/srv/people/bob) — a recursive relabel of the ancestor still walks through the
// user's units. Manifest-time validation cannot know an admin-chosen home root, so
// the verifier is asked: /etc/passwd lists the real ones.
func TestDeclaredRootsAgainstRealHomes(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"bin:x:1:1:bin:/bin:/sbin/nologin\n" +
		"nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin\n" +
		"bob:x:1000:1000:Bob:/srv/people/bob:/bin/bash\n"

	newRunner := func() *fakeRunner {
		return &fakeRunner{responses: map[string]string{"passwd": passwd}}
	}

	// The ANCESTOR of a custom home must be rejected.
	p := &profile.Profile{
		Name:        "bob",
		Executables: []string{"/opt/bob/bin/bobd"},
		Paths:       []profile.PathAccess{{Path: "/srv/people/bob(/.*)?", Kind: "conf"}},
	}
	err := checkDeclaredRootsAgainstHomes(newRunner(), p)
	if err == nil || !strings.Contains(err.Error(), "home directory of user") {
		t.Fatalf("a claim on a custom home root must be rejected, got %v", err)
	}

	// A path UNDER that home must be rejected too.
	p2 := &profile.Profile{
		Name:        "bob",
		Executables: []string{"/opt/bob/bin/bobd"},
		Paths:       []profile.PathAccess{{Path: "/srv/people/bob/.config/systemd/user(/.*)?", Kind: "conf"}},
	}
	if err := checkDeclaredRootsAgainstHomes(newRunner(), p2); err == nil {
		t.Error("a path under a custom home must be rejected")
	}

	// An ANCESTOR of the home tree (/srv/people) must be rejected — restorecon -RF
	// there still reaches the user's units.
	p3 := &profile.Profile{
		Name:        "people",
		Executables: []string{"/opt/people/bin/peopled"},
		Paths:       []profile.PathAccess{{Path: "/srv/people(/.*)?", Kind: "conf"}},
	}
	if err := checkDeclaredRootsAgainstHomes(newRunner(), p3); err == nil {
		t.Error("an ancestor of a custom home must be rejected")
	}

	// An ordinary system path is unaffected — and the pseudo-user with home "/"
	// must NOT cause a blanket rejection.
	ok := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	if err := checkDeclaredRootsAgainstHomes(newRunner(), ok); err != nil {
		t.Errorf("an ordinary system path must pass (and home=/ must be skipped): %v", err)
	}

	// An unreadable passwd database fails closed.
	bad := &fakeRunner{responses: map[string]string{}, failOn: []string{"passwd"}}
	if err := checkDeclaredRootsAgainstHomes(bad, ok); err == nil {
		t.Error("an unreadable passwd database must fail closed")
	}
}
