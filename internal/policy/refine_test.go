package policy

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/avc"
	"github.com/testifysec/hardener/internal/profile"
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

// Round 42: process/process2 permissions use a fail-closed ALLOWLIST — context-
// manipulation perms (setexec, setcap, ...) must be flagged, benign ones not.
func TestProcessPermsAreAllowlisted(t *testing.T) {
	p := widgetProfile()
	for _, perm := range []string{"setexec", "setcurrent", "setfscreate", "setkeycreate", "setsockcreate", "setcap", "dyntransition"} {
		ds := []avc.Denial{{SourceType: "widget_t", TargetType: "widget_t", Class: "process", Perms: []string{perm}}}
		res := Refine(p, ds)
		if len(res.Flags) == 0 {
			t.Errorf("privileged process perm %q must be flagged for review", perm)
		}
	}
	// Benign self-process perms are not flagged.
	ds := []avc.Denial{{SourceType: "widget_t", TargetType: "widget_t", Class: "process", Perms: []string{"fork", "sigchld", "signal"}}}
	if res := Refine(p, ds); len(res.Flags) != 0 {
		t.Errorf("benign process perms must not be flagged: %+v", res.Flags)
	}
}

// Round 43: the canonical exec-set expansion must UNION with observed perms, not
// replace them — a `{ execute write }` denial on an _exec_t target must keep
// `write` so the self-modification check still fires.
func TestCanonicalExecUnionsObservedPerms(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "widget_exec_t", Class: "file",
		Perms: []string{"execute", "write"},
	}}
	res := Refine(p, ds)
	// write to the app's own exec_t is self-modification → must be flagged.
	flagged := false
	for _, f := range res.Flags {
		if strings.Contains(f.Reason, "self-modification") {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("write must survive the canonical-exec expansion and be flagged: %+v", res.Flags)
	}
}

// Round 46: FlagDeclaredCapabilities must emit each declared capability under its
// correct class — bpf/perfmon are capability2 (a capability-class artifact would
// be uncompilable if accepted).
func TestFlagDeclaredCapabilitiesPartitionsByClass(t *testing.T) {
	flags := FlagDeclaredCapabilities("widget", []string{"bpf", "perfmon", "sys_admin"})
	byClass := map[string]string{}
	for _, f := range flags {
		byClass[f.Rule.Perms[0]] = f.Rule.Class
	}
	if byClass["bpf"] != "capability2" || byClass["perfmon"] != "capability2" {
		t.Errorf("bpf/perfmon must be capability2, got %v", byClass)
	}
	if byClass["sys_admin"] != "capability" {
		t.Errorf("sys_admin must be capability, got %q", byClass["sys_admin"])
	}
}

// Round 46: two mislabeled entrypoints that would collapse under avc.Merge (same
// source/target/class, empty path) must be classified per-denial before merging,
// so BOTH surface.
func TestEntrypointsClassifiedBeforeMerge(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{
		{SourceType: "init_t", TargetType: "widget_content_t", Class: "file", Perms: []string{"execute"}, Name: "wd1"},
		{SourceType: "init_t", TargetType: "widget_content_t", Class: "file", Perms: []string{"execute"}, Name: "wd2"},
	}
	res := Refine(p, ds)
	if len(res.Entrypoints) != 2 {
		t.Errorf("both mislabeled entrypoints must be detected before merge collapses them, got %d: %+v", len(res.Entrypoints), res.Entrypoints)
	}
}

// A W^X violation on an owned CONFIG type (_conf_t) matches none of Refine's
// per-denial suffix buckets (_content_t/_exec_t self-modification, or the
// writable data suffixes), so the accumulated rule ships unflagged unless the
// cumulative scan catches it. This is the exact code-injection primitive Codex
// flagged: executable, application-writable configuration.
func TestFlagWriteExecRulesFlagsOwnedConfType(t *testing.T) {
	p := widgetProfile()
	rules := []AllowRule{
		{Source: "widget_t", Target: "widget_conf_t", Class: "file", Perms: []string{"write", "execute", "execute_no_trans"}},
	}
	flags := FlagWriteExecRules(p, rules)
	if len(flags) != 1 {
		t.Fatalf("owned _conf_t with write+execute must be flagged, got %+v", flags)
	}
	if !strings.Contains(flags[0].Reason, "W^X") || !strings.Contains(flags[0].Reason, "widget_conf_t") {
		t.Errorf("flag reason: %q", flags[0].Reason)
	}
}

// The cross-round accumulation case: a write granted in one refinement round and
// an execute in another merge (via normalizeRules) into a single owned-type rule.
// Neither half is dangerous alone, but the union is a W^X violation the
// per-round refiner cannot see. FlagWriteExecRules scans the merged set.
func TestFlagWriteExecRulesCatchesMergedWriteAndExecute(t *testing.T) {
	p := widgetProfile()
	// write-only alone: not a violation.
	if f := FlagWriteExecRules(p, []AllowRule{{Source: "widget_t", Target: "widget_conf_t", Class: "file", Perms: []string{"write"}}}); len(f) != 0 {
		t.Errorf("write-only must not be flagged, got %+v", f)
	}
	// execute-only alone: not a violation (executing a read-only config is fine).
	if f := FlagWriteExecRules(p, []AllowRule{{Source: "widget_t", Target: "widget_conf_t", Class: "file", Perms: []string{"execute"}}}); len(f) != 0 {
		t.Errorf("execute-only must not be flagged, got %+v", f)
	}
	// The merged rule (both perms on the same owned target) IS a violation.
	merged := []AllowRule{{Source: "widget_t", Target: "widget_conf_t", Class: "file", Perms: []string{"execute", "write"}}}
	if f := FlagWriteExecRules(p, merged); len(f) != 1 {
		t.Fatalf("merged write+execute must be flagged, got %+v", f)
	}
}

// read+execute (no content-modifying perm) is not W^X, and a FOREIGN type is not
// this scanner's concern (Refine's foreign-type check owns that path) — guard
// against over-flagging both.
func TestFlagWriteExecRulesIgnoresReadExecAndForeign(t *testing.T) {
	p := widgetProfile()
	if f := FlagWriteExecRules(p, []AllowRule{{Source: "widget_t", Target: "widget_conf_t", Class: "file", Perms: []string{"read", "open", "execute"}}}); len(f) != 0 {
		t.Errorf("read+execute is not W^X, got %+v", f)
	}
	if f := FlagWriteExecRules(p, []AllowRule{{Source: "widget_t", Target: "foreign_conf_t", Class: "file", Perms: []string{"write", "execute"}}}); len(f) != 0 {
		t.Errorf("foreign type is not owned; this scanner must ignore it, got %+v", f)
	}
}

// Powerful kernel object classes (bpf, perf_event, io_uring) must go to review
// even when the target is the app's OWN type — the foreign-type gate never sees
// an owned self-target, and dangerReason otherwise ignores the object class, so
// these auto-applied unreviewed. (review finding — round 56)
func TestDangerousObjectClassesFlaggedEvenWhenOwned(t *testing.T) {
	p := widgetProfile()
	for _, tc := range []struct{ class, perm string }{
		{"bpf", "prog_load"},
		{"perf_event", "open"},
		{"io_uring", "sqpoll"},
	} {
		ds := []avc.Denial{{
			SourceType: "widget_t", TargetType: "widget_t", Class: tc.class, Perms: []string{tc.perm},
		}}
		res := Refine(p, ds)
		flagged := false
		for _, f := range res.Flags {
			if strings.Contains(f.Reason, "privileged object class") && strings.Contains(f.Reason, tc.class) {
				flagged = true
			}
		}
		if !flagged {
			t.Errorf("%s:%s on an owned self-target must be flagged for review, got %+v", tc.class, tc.perm, res.Flags)
		}
		// Flagged rules must NOT silently ship in the auto-apply set.
		for _, r := range res.AllowRules {
			if r.Class == tc.class {
				t.Errorf("%s rule must be dropped from auto-apply until reviewed, got %+v", tc.class, r)
			}
		}
	}
}

// A domain acting on ITSELF with an unusual class must go to review: memprotect
// (mmap_zero — a NULL-page-mapping exploit primitive) and any class outside the
// benign self-target allowlist. Benign self classes (own sockets/IPC) still
// auto-apply. (review finding — round 58)
func TestSelfTargetClassesAreFailClosedAllowlist(t *testing.T) {
	p := widgetProfile()

	// memprotect:mmap_zero on the domain's own type must be flagged.
	res := Refine(p, []avc.Denial{{SourceType: "widget_t", TargetType: "widget_t", Class: "memprotect", Perms: []string{"mmap_zero"}}})
	if !anyFlagContains(res.Flags, "memprotect") {
		t.Errorf("memprotect:mmap_zero on a self-target must be flagged, got %+v", res.Flags)
	}

	// An exotic/unknown self-target class must be flagged by the fail-closed allowlist.
	res = Refine(p, []avc.Denial{{SourceType: "widget_t", TargetType: "widget_t", Class: "netlink_audit_socket", Perms: []string{"nlmsg_write"}}})
	if !anyFlagContains(res.Flags, "self-target class") {
		t.Errorf("an unrecognized self-target class must be flagged, got %+v", res.Flags)
	}

	// A benign self-target class (own tcp_socket) must NOT be flagged.
	res = Refine(p, []avc.Denial{{SourceType: "widget_t", TargetType: "widget_t", Class: "tcp_socket", Perms: []string{"create", "listen"}}})
	for _, f := range res.Flags {
		if strings.Contains(f.Reason, "self-target class") {
			t.Errorf("a benign self-target class must not be flagged: %+v", f)
		}
	}
}

func anyFlagContains(flags []Flag, sub string) bool {
	for _, f := range flags {
		if strings.Contains(f.Reason, sub) {
			return true
		}
	}
	return false
}

// SELinux labels a file by the MOST-SPECIFIC file_contexts entry. expectedType
// returns the first matcher, so a broad claim listed BEFORE a nested one would
// misread a correctly-labeled nested file as relabel drift (and could suppress a
// W^X/review finding). compileFCMatchers must order most-specific first.
// (review finding — round 61)
func TestFCMatcherPrefersMostSpecific(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths: []profile.PathAccess{
			{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"},         // BROAD, listed first
			{Path: "/var/lib/widget/plugins(/.*)?", Kind: "content"}, // NESTED, listed second
		},
	}
	ms := compileFCMatchers(p)
	if got, ok := expectedType(ms, "/var/lib/widget/plugins/x.so", "file"); !ok || got != "widget_content_t" {
		t.Errorf("nested path must resolve to the most-specific type widget_content_t, got %q (ok=%v)", got, ok)
	}
	if got, ok := expectedType(ms, "/var/lib/widget/state.db", "file"); !ok || got != "widget_var_lib_t" {
		t.Errorf("a file only under the broad path must resolve to widget_var_lib_t, got %q", got)
	}
	// The exact executable still wins over any tree claim covering it.
	if got, ok := expectedType(ms, "/opt/widget/bin/widgetd", "file"); !ok || got != "widget_exec_t" {
		t.Errorf("exact executable must resolve to widget_exec_t, got %q", got)
	}
}

// An executable file-context maps with the SELinux `--` selector (regular files
// only). A symlink or directory sharing that exact path is NOT labeled _exec_t;
// a less-specific unselected claim covering the tree applies instead. expectedType
// must honor the selector by class, or a correctly-labeled symlink/dir under an
// executable path is misread as relabel drift toward _exec_t — suppressing the
// symlink's real denial and blocking refinement convergence. (review finding — round 65)
func TestFCMatcherHonorsExecSelectorByClass(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths: []profile.PathAccess{
			// A content claim OVERLAPS the executable path (the exec lives under it).
			{Path: "/opt/widget(/.*)?", Kind: "content"},
		},
	}
	ms := compileFCMatchers(p)
	// A REGULAR FILE at the exec path is the executable: _exec_t (selector applies).
	if got, ok := expectedType(ms, "/opt/widget/bin/widgetd", "file"); !ok || got != "widget_exec_t" {
		t.Errorf("regular file at exec path must resolve to widget_exec_t, got %q (ok=%v)", got, ok)
	}
	// A SYMLINK at the same path is NOT _exec_t — the `--` selector excludes it, so
	// the overlapping content claim applies. Reporting _exec_t here would be a false
	// relabel that discards the symlink's genuine denial.
	if got, ok := expectedType(ms, "/opt/widget/bin/widgetd", "lnk_file"); !ok || got != "widget_content_t" {
		t.Errorf("symlink at exec path must fall through to widget_content_t, got %q (ok=%v)", got, ok)
	}
	// A DIRECTORY at the same path likewise falls through to the content claim.
	if got, ok := expectedType(ms, "/opt/widget/bin/widgetd", "dir"); !ok || got != "widget_content_t" {
		t.Errorf("directory at exec path must fall through to widget_content_t, got %q (ok=%v)", got, ok)
	}
}
