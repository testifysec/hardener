package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 78: `gone` was scoped INSIDE the removal retry loop, so cleanup proceeded
// after two FAILED `semodule -r` attempts as if the module were gone — and then
// ran restorecon, REAPPLYING the still-loaded module's own labels and silently
// contaminating the persistent verifier. An unconfirmed removal must skip the
// relabel and report loudly.
func TestCleanupSkipsRelabelWhenModuleRemovalUnconfirmed(t *testing.T) {
	f := passingRunner()
	// The early name-conflict probes must see a CLEAN list (otherwise the run
	// aborts before install and cleanup never touches the module). After those, the
	// list permanently contains widget — the last seq entry sticks — so cleanup's
	// removal verification never confirms removal. widget is in expectedMods, so
	// the intervening recheck calls are unaffected.
	f.seq = map[string][]string{
		"semodule -l": {
			"base\nselinux-policy\nunconfined\n", // nameConflict (pre-install)
			"base\nselinux-policy\nunconfined\n", // nameConflict (post-install)
			"base\nselinux-policy\nunconfined\nwidget\n",
		},
	}
	f.responses["-t shadow_t"] = "allow widget_t shadow_t:file read;" // force a failure → cleanup
	res := Run(f, testTarget(), Options{MaxRounds: 2})
	if res.FailureReason == "" {
		t.Fatal("expected a failure so cleanup runs")
	}
	if f.countCalls("semodule -r widget") == 0 {
		t.Fatal("cleanup must attempt removal")
	}
	// The relabel must NOT run: it would reapply the still-loaded module's labels.
	for _, c := range f.calls {
		if strings.Contains(c, "restorecon -RF") && strings.Contains(c, "/var/lib/widget") {
			t.Error("cleanup must not relabel while the module is still loaded — that reapplies its own types")
		}
	}
}

// Conversely, a confirmed removal must still restore base labels.
func TestCleanupRelabelsWhenModuleRemovalConfirmed(t *testing.T) {
	f := passingRunner() // semodule -l does not list widget → removal confirmed
	f.responses["-t shadow_t"] = "allow widget_t shadow_t:file read;"
	if res := Run(f, testTarget(), Options{MaxRounds: 2}); res.FailureReason == "" {
		t.Fatal("expected a failure so cleanup runs")
	}
	found := false
	for _, c := range f.calls {
		if strings.Contains(c, "restorecon -RF") {
			found = true
			break
		}
	}
	if !found {
		t.Error("a confirmed removal must still restore base labels")
	}
}

// Round 78: the descendant scan only sees objects that EXIST, so a more-specific
// BASE-policy rule beneath an empty or not-yet-created declared root is missed —
// files the app later creates there get the base type while the signed result
// claims the root is confined. The check must be independent of disk contents,
// and must NOT flag our own module's entries (the compiled file_contexts contains
// them after install, plus earlier hardener modules' entries on a reused verifier).
func TestBaseRuleUnderDeclaredRootIsRejected(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	// A FOREIGN base rule strictly under our declared root must be rejected.
	f := &fakeRunner{responses: map[string]string{
		"cat /etc/selinux/targeted/contexts/files/file_contexts": "" +
			"/var/lib(/.*)?\tsystem_u:object_r:var_lib_t:s0\n" +
			"/var/lib/widget/secrets(/.*)?\tsystem_u:object_r:shadow_t:s0\n",
	}}
	err := checkBaseRulesUnderRoots(f, p)
	if err == nil || !strings.Contains(err.Error(), "applies under declared root") {
		t.Fatalf("a foreign base rule under the declared root must be rejected, got %v", err)
	}
	if !strings.Contains(err.Error(), "shadow_t") {
		t.Errorf("the error should name the overriding type: %v", err)
	}

	// OUR OWN entries (and a sub-root we declared) must NOT trip it.
	f2 := &fakeRunner{responses: map[string]string{
		"cat /etc/selinux/targeted/contexts/files/file_contexts": "" +
			"/var/lib/widget(/.*)?\tsystem_u:object_r:widget_var_lib_t:s0\n" +
			"/var/lib/widget/sub(/.*)?\tsystem_u:object_r:widget_content_t:s0\n" +
			"/opt/widget/bin/widgetd\t--\tsystem_u:object_r:widget_exec_t:s0\n",
	}}
	if err := checkBaseRulesUnderRoots(f2, p); err != nil {
		t.Errorf("our own generated types must not be flagged: %v", err)
	}

	// An ANCESTOR rule is not more specific than our root and must not trip it.
	f3 := &fakeRunner{responses: map[string]string{
		"cat /etc/selinux/targeted/contexts/files/file_contexts": "/var/lib(/.*)?\tsystem_u:object_r:var_lib_t:s0\n",
	}}
	if err := checkBaseRulesUnderRoots(f3, p); err != nil {
		t.Errorf("an ancestor rule must not be flagged: %v", err)
	}

	// A read failure must fail closed.
	f4 := &fakeRunner{responses: map[string]string{}, failOn: []string{"file_contexts"}}
	if err := checkBaseRulesUnderRoots(f4, p); err == nil {
		t.Error("an unreadable file_contexts must fail closed")
	}
}
