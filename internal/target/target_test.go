package target

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const portManifest = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
ports:
  - { proto: %s, port: %d }
`

// Round 17: port proto/number are interpolated into root %post semanage
// commands, so an unvalidated protocol could smuggle shell metacharacters and
// an out-of-range port is meaningless. Load must reject both.
func TestLoadValidatesPorts(t *testing.T) {
	bad := []struct {
		proto string
		port  int
	}{
		{"sctp", 80}, {"tcp; rm -rf /", 80}, {"tcp", 0}, {"udp", 70000}, {"tcp", -1},
	}
	for _, b := range bad {
		if _, err := Load(write(t, fmt.Sprintf(portManifest, b.proto, b.port))); err == nil {
			t.Errorf("port %q/%d must be rejected", b.proto, b.port)
		}
	}
	for _, ok := range []struct {
		proto string
		port  int
	}{{"tcp", 8443}, {"udp", 1}, {"tcp", 65535}} {
		if _, err := Load(write(t, fmt.Sprintf(portManifest, ok.proto, ok.port))); err != nil {
			t.Errorf("port %q/%d must load: %v", ok.proto, ok.port, err)
		}
	}
}

const validManifest = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: "/etc/widget(/.*)?", kind: %s }
`

func write(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Round 14: an unknown or omitted path kind must be REJECTED at load, not
// silently mapped to content (content paths get can_exec, so a typo could make
// a config file executable).
func TestLoadRejectsUnknownKind(t *testing.T) {
	for _, bad := range []string{"confg", "CONF", "executable", ""} {
		body := strings.Replace(validManifest, "%s", bad, 1)
		if bad == "" {
			// render an explicit empty kind
			body = strings.Replace(validManifest, "kind: %s", "kind: \"\"", 1)
		}
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("kind %q must be rejected", bad)
		} else if !strings.Contains(err.Error(), "kind") {
			t.Errorf("error for kind %q should mention kind, got %v", bad, err)
		}
	}
}

// Every valid kind still loads.
func TestLoadAcceptsKnownKinds(t *testing.T) {
	// "exec" is a valid Kind but is rejected in PATHS (entrypoints go in
	// executables) — see TestLoadRejectsExecPaths.
	for _, ok := range []string{"conf", "var_lib", "log", "runtime", "content", "tmp", "cache", "unit"} {
		body := strings.Replace(validManifest, "%s", ok, 1)
		if _, err := Load(write(t, body)); err != nil {
			t.Errorf("kind %q must load, got %v", ok, err)
		}
	}
}

const broadPathManifest = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: "%s", kind: content }
`

// Round 22: a manifest must not claim a broad system tree — %post restorecon -RF
// on it would relabel large parts of the customer filesystem.
func TestLoadRejectsBroadPaths(t *testing.T) {
	for _, bad := range []string{"/usr(/.*)?", "/(/.*)?", "/etc(/.*)?", "/var/lib(/.*)?", "/usr/bin(/.*)?", "/opt(/.*)?"} {
		if _, err := Load(write(t, fmt.Sprintf(broadPathManifest, bad))); err == nil {
			t.Errorf("broad path %q must be rejected", bad)
		}
	}
	for _, ok := range []string{"/etc/widget(/.*)?", "/var/lib/widget(/.*)?", "/opt/widget(/.*)?", "/usr/lib/widget(/.*)?"} {
		if _, err := Load(write(t, fmt.Sprintf(broadPathManifest, ok))); err != nil {
			t.Errorf("bounded path %q must load: %v", ok, err)
		}
	}
}

// Round 23: kind:exec in a PATH bypasses the app-ownership check (GenerateFC
// maps it straight to <app>_exec_t) — it must be rejected; entrypoints go in
// the executables list.
func TestLoadRejectsExecPaths(t *testing.T) {
	m := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: "/usr/bin/curl", kind: exec }
`
	if _, err := Load(write(t, m)); err == nil {
		t.Error("kind:exec in paths must be rejected")
	} else if !strings.Contains(err.Error(), "exec") {
		t.Errorf("error should mention exec: %v", err)
	}
}

const pathManifest = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: %q, kind: conf }
`

// Round 24 (#1): a path must be positively app-owned (a literal root component
// ties to the app name) and free of newline/control bytes — otherwise a
// manifest could have %post restorecon relabel an unrelated system file, or
// inject extra file-context records via an embedded newline.
func TestLoadRejectsUnownedAndInjectionPaths(t *testing.T) {
	bad := []string{
		"/etc/passwd",                             // unrelated system file, not app-owned
		"/usr/lib64/libc.so.6",                    // shared library, not app-owned
		"/var/lib/other(/.*)?",                    // app-specific shape but ties to "other"
		"/etc/widget\n/etc/shadow gen_context(x)", // newline injection
		"/etc/widget\x00evil",                     // NUL byte
		// Round 25: a non-boundary prefix is NOT ownership — "widgetsrv" and
		// "widgetd" merely start with "widget" (same shape as dock→docker), so
		// they must be rejected unless explicitly vouched for with owned: true.
		"/usr/lib/widgetsrv(/.*)?",
		"/opt/widgetd/data(/.*)?",
		// Round 26: path traversal — the literal root resolves through
		// restorecon to a broad tree (/etc/widget/../.. -> /).
		"/etc/widget/../..(/.*)?",
		"/var/lib/widget/../../../etc(/.*)?",
		"relative/widget(/.*)?", // not absolute
		// Round 27: regex alternation — literal root is /etc/widget but the
		// expression is emitted verbatim and also matches /etc/shadow.
		"/etc/widget(/.*)?|/etc/shadow",
		"/var/lib/widget(/.*)?|/etc(/.*)?",
		"/etc/widget[a-z]*",    // non-terminal regex operators
		"/etc/wid(get)?(/.*)?", // interior optional group
		// Round 30: non-canonical roots — the kernel resolves the doubled slash /
		// dot, so /var//lib bypasses the broad-root map but relabels /var/lib.
		"/var//lib(/.*)?",
		"/etc//widget(/.*)?",
		"/etc/./widget(/.*)?",
	}
	for _, p := range bad {
		if _, err := Load(write(t, fmt.Sprintf(pathManifest, p))); err == nil {
			t.Errorf("path %q must be rejected", p)
		}
	}
	// App-owned paths tie to the app at a TOKEN BOUNDARY: exact match, or one is
	// the other plus an underscore-delimited token (widget ↔ widget_data).
	for _, ok := range []string{
		"/etc/widget(/.*)?",
		"/var/lib/widget(/.*)?",
		"/opt/widget_data(/.*)?",
	} {
		if _, err := Load(write(t, fmt.Sprintf(pathManifest, ok))); err != nil {
			t.Errorf("app-owned path %q must load: %v", ok, err)
		}
	}
}

// Round 25: a non-boundary vendor directory (plexmediaserver for plex) cannot
// be confirmed by the name heuristic, so it must carry an explicit owned: true
// to be accepted — turning a silent heuristic pass into a reviewable claim. The
// override does NOT relax the broad-system-root guard.
func TestLoadOwnedOverrideForVendorDirs(t *testing.T) {
	const ownedManifest = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: %q, kind: content, owned: %v }
`
	// Non-boundary vendor dir: rejected without owned, accepted with it.
	if _, err := Load(write(t, fmt.Sprintf(ownedManifest, "/usr/lib/widgetmediaserver(/.*)?", false))); err == nil {
		t.Error("non-boundary vendor dir must be rejected without owned: true")
	}
	if _, err := Load(write(t, fmt.Sprintf(ownedManifest, "/usr/lib/widgetmediaserver(/.*)?", true))); err != nil {
		t.Errorf("owned: true must accept a vendor dir: %v", err)
	}
	// owned: true must NOT let a broad system root through.
	if _, err := Load(write(t, fmt.Sprintf(ownedManifest, "/usr(/.*)?", true))); err == nil {
		t.Error("owned: true must not override the broad-system-root guard")
	}
}

// Round 31: unknown manifest fields must be REJECTED — a typo like `partyy:`
// would otherwise be silently ignored, leaving Party empty (third-party) and
// dropping the fail-closed conformance rules for a second-party artifact.
func TestLoadRejectsUnknownField(t *testing.T) {
	m := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
partyy: second
`
	if _, err := Load(write(t, m)); err == nil {
		t.Error("an unknown/misspelled manifest field must be rejected")
	}
}

// Round 32: whitespace/control in a path is a file-context FIELD injection —
// "/etc/widget/config --" splits into a path plus an fc selector.
func TestLoadRejectsWhitespaceInPath(t *testing.T) {
	for _, bad := range []string{
		"/etc/widget/config --",
		"/etc/widget\tconfig(/.*)?",
		"/etc/widget config(/.*)?",
	} {
		if _, err := Load(write(t, fmt.Sprintf(pathManifest, bad))); err == nil {
			t.Errorf("path %q with whitespace must be rejected", bad)
		}
	}
}

// Round 33: a multi-document manifest must be rejected — content after `---`
// would be silently dropped, potentially discarding party/declaration and
// producing evidence under weaker rules.
func TestLoadRejectsMultiDocument(t *testing.T) {
	m := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
party: second
declared: {}
---
party: third
`
	if _, err := Load(write(t, m)); err == nil {
		t.Error("a multi-document manifest must be rejected")
	}
}

// Round 35: a GENERIC parent directory component must not confer ownership just
// because a compound app name starts with it — `system-widget` claiming
// /etc/systemd/system would relabel every local unit file.
func TestLoadRejectsGenericComponentTie(t *testing.T) {
	m := `name: system-widget
install: "true"
unit: system-widget.service
exercise: "true"
executables:
  - /opt/system-widget/bin/swd
paths:
  - { path: "/etc/systemd/system(/.*)?", kind: conf }
`
	if _, err := Load(write(t, m)); err == nil {
		t.Error("a generic-component tie (system → system-widget) must be rejected without owned: true")
	}
}

// Round 37: an EXACT match on a generic component must not confer ownership —
// an app named `services` must not claim /etc/services without owned: true.
func TestLoadRejectsExactGenericComponent(t *testing.T) {
	m := `name: services
install: "true"
unit: services.service
exercise: "true"
executables:
  - /opt/services/bin/svc
paths:
  - { path: "/etc/services(/.*)?", kind: conf }
`
	if _, err := Load(write(t, m)); err == nil {
		t.Error("an app named after a generic component must not claim it without owned: true")
	}
}

// Round 40: shared systemd unit trees must be rejected even WITH owned: true —
// relabeling them rewrites every service's unit files.
func TestLoadRejectsSystemdUnitTreesEvenWhenOwned(t *testing.T) {
	const m = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: %q, kind: conf, owned: true }
`
	for _, p := range []string{
		"/etc/systemd/system(/.*)?",
		"/usr/lib/systemd/system(/.*)?",
		"/etc/systemd/system/multi-user.target.wants(/.*)?",
		"/run/systemd/system(/.*)?",
	} {
		if _, err := Load(write(t, fmt.Sprintf(m, p))); err == nil {
			t.Errorf("systemd unit tree %q must be rejected even with owned: true", p)
		}
	}
}

// Round 41: executables must be validated for path-safety (absolute, canonical,
// no traversal/control) — Load previously only checked the list was non-empty.
func TestLoadValidatesExecutablePaths(t *testing.T) {
	tmpl := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - %s
`
	for _, bad := range []string{
		"relative/widgetd",         // not absolute
		"/opt/widget/../../bin/sh", // traversal
		"/opt//widget/bin/widgetd", // non-canonical
		"/opt/widget/bin/wd\ttab",  // control char
	} {
		if _, err := Load(write(t, fmt.Sprintf(tmpl, bad))); err == nil {
			t.Errorf("executable %q must be rejected", bad)
		}
	}
	// A vendor binary WITH SPACES is still allowed (Plex Media Server).
	if _, err := Load(write(t, fmt.Sprintf(tmpl, `"/usr/lib/plexmediaserver/Plex Media Server"`))); err != nil {
		t.Errorf("a space-containing vendor binary must load: %v", err)
	}
}

// Round 64: a '%' in a path or executable must be rejected. GenerateSpec
// interpolates these into the RPM spec, and rpmbuild expands %{...}/%(...) macros
// throughout the spec — including %post scriptlets and the HARDENER_ROOTS heredoc —
// BEFORE the shell runs. ShellQuote guards the shell, not rpmbuild, so a '%' would
// let a manifest execute a command at build time or expand a macro, diverging the
// signed RPM from the verified policy (review finding).
func TestLoadRejectsRPMMacroInjection(t *testing.T) {
	// Paths: '%' must be rejected regardless of ownership (the check runs early).
	for _, bad := range []string{
		"/opt/widget%(id)/config",   // %(...) command expansion at rpmbuild time
		"/opt/widget/%{_bindir}",    // %{...} macro expansion
		"/opt/widget/conf%",         // bare percent
	} {
		_, err := Load(write(t, fmt.Sprintf(pathManifest, bad)))
		if err == nil {
			t.Errorf("path %q with '%%' must be rejected", bad)
			continue
		}
		if !strings.Contains(err.Error(), "macro-expand") {
			t.Errorf("path %q: expected an rpmbuild macro-expansion rejection, got: %v", bad, err)
		}
	}
	// Executables: same rule (spaces are allowed, but '%' is not).
	exeTmpl := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - %s
`
	for _, bad := range []string{
		`"/opt/widget/bin/%(id)"`,
		`"/opt/widget/bin/wd%{nil}"`,
	} {
		_, err := Load(write(t, fmt.Sprintf(exeTmpl, bad)))
		if err == nil {
			t.Errorf("executable %q with '%%' must be rejected", bad)
			continue
		}
		if !strings.Contains(err.Error(), "macro-expand") {
			t.Errorf("executable %q: expected an rpmbuild macro-expansion rejection, got: %v", bad, err)
		}
	}
}

// Round 45: a `declared:` block requires party: second, and a `baseline:`
// requires party: first — otherwise a supplier silently gets weaker third-party
// handling and a passing attestation.
func TestLoadRejectsDeclaredOrBaselineWithoutMatchingParty(t *testing.T) {
	declaredNoParty := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
declared: {}
`
	if _, err := Load(write(t, declaredNoParty)); err == nil {
		t.Error("declared: without party: second must be rejected")
	}
	baselineWrongParty := `name: widget
install: "true"
unit: widget.service
exercise: "true"
party: third
executables:
  - /opt/widget/bin/widgetd
baseline: baselines/widget.yaml
`
	if _, err := Load(write(t, baselineWrongParty)); err == nil {
		t.Error("baseline: without party: first must be rejected")
	}
}

// Round 47: /var/run is a symlink to /run on RHEL, so a /var/run/systemd/system
// claim must be rejected even with owned: true (it resolves to the shared unit
// tree).
func TestLoadRejectsVarRunSystemdTrees(t *testing.T) {
	const m = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: %q, kind: conf, owned: true }
`
	for _, p := range []string{
		"/var/run/systemd/system(/.*)?",
		"/var/run/systemd/user(/.*)?",
		"/var/run/systemd/system/foo.service.d(/.*)?",
	} {
		if _, err := Load(write(t, fmt.Sprintf(m, p))); err == nil {
			t.Errorf("%s must be rejected even with owned: true", p)
		}
	}
}

// /usr/local/lib/systemd is the local-admin tier of systemd's unit load path;
// claiming it (or a descendant) with owned: true would let restorecon -RF
// relabel every locally installed unit. Reject it like the other shared trees.
// (review finding — round 49)
func TestLoadRejectsUsrLocalLibSystemdTrees(t *testing.T) {
	const m = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: %q, kind: conf, owned: true }
`
	for _, p := range []string{
		"/usr/local/lib/systemd/system(/.*)?",
		"/usr/local/lib/systemd/user(/.*)?",
		"/usr/local/lib/systemd/system/widget.service.d(/.*)?",
	} {
		if _, err := Load(write(t, fmt.Sprintf(m, p))); err == nil {
			t.Errorf("%s must be rejected even with owned: true", p)
		}
	}
}

// A claim ABOVE a protected systemd tree (a parent that CONTAINS it) is as
// dangerous as claiming the tree itself: restorecon -RF on the parent relabels
// every shared unit beneath. isSharedSystemdTree must reject ancestors too, not
// only the tree and its descendants. (review finding — round 52)
func TestLoadRejectsSystemdParentTrees(t *testing.T) {
	const m = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: %q, kind: conf, owned: true }
`
	for _, p := range []string{
		"/run/systemd(/.*)?",
		"/lib/systemd(/.*)?",
		"/usr/local/lib/systemd(/.*)?",
		"/var/run/systemd(/.*)?",
	} {
		if _, err := Load(write(t, fmt.Sprintf(m, p))); err == nil {
			t.Errorf("%s (parent of a protected unit tree) must be rejected even with owned: true", p)
		}
	}
}

// Guard against over-rejection: a bounded app dir under /run that merely shares
// the /run prefix with a protected tree must still be allowed.
func TestLoadAllowsBoundedRunAppDir(t *testing.T) {
	const m = `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: "/run/widget(/.*)?", kind: runtime }
`
	if _, err := Load(write(t, m)); err != nil {
		t.Errorf("/run/widget is a legitimate bounded runtime dir, must load: %v", err)
	}
}

// GenerateFC would emit overlapping entries with different types for the same
// path, which semodule rejects. Conflicting in-profile claims must be caught at
// manifest load. (review finding — round 63)
func TestLoadRejectsConflictingFileContextClaims(t *testing.T) {
	// Same path, two different kinds.
	dupKind := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: "/var/lib/widget(/.*)?", kind: var_lib }
  - { path: "/var/lib/widget(/.*)?", kind: content }
`
	if _, err := Load(write(t, dupKind)); err == nil {
		t.Error("same path with two different kinds must be rejected")
	}

	// An executable path also declared as a data path.
	execAsPath := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: "/opt/widget/bin/widgetd", kind: content, owned: true }
`
	if _, err := Load(write(t, execAsPath)); err == nil {
		t.Error("an executable also declared as a path must be rejected")
	}

	// An exact duplicate (same path, same kind) is idempotent, not a conflict.
	dupSame := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: "/var/lib/widget(/.*)?", kind: var_lib }
  - { path: "/var/lib/widget(/.*)?", kind: var_lib }
`
	if _, err := Load(write(t, dupSame)); err != nil {
		t.Errorf("an exact duplicate path+kind is idempotent, must load: %v", err)
	}
}

// Round 70: a duplicate (proto, port) must be rejected at load. %postun tests
// every declared entry against ONE stale `semanage port -l` snapshot, so the
// second copy still matches after the first deletion removed the mapping; the
// repeated `semanage port -d` then fails and the fail-closed handler aborts the
// uninstall before `semodule -r` and the label restore, leaving the module and
// stale labels behind after an RPM erase. (review finding)
func TestLoadRejectsDuplicatePorts(t *testing.T) {
	m := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
ports:
  - { proto: tcp, port: 8443 }
  - { proto: tcp, port: 8443 }
`
	_, err := Load(write(t, m))
	if err == nil {
		t.Fatal("a duplicate proto/port must be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate port") {
		t.Errorf("expected a duplicate-port rejection, got: %v", err)
	}
	// Same port number on a DIFFERENT protocol is legitimate and must load.
	ok := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
ports:
  - { proto: tcp, port: 8443 }
  - { proto: udp, port: 8443 }
`
	if _, err := Load(write(t, ok)); err != nil {
		t.Errorf("tcp and udp on the same port number must load: %v", err)
	}
}

// Round 78: the protected systemd list enumerated only the ".../system" and
// ".../user" directories, missing the SIBLING unit-load directories systemd
// actually reads — /run/systemd/transient, the .control trees, the generator
// trees, the .attached trees. None of those are under or above ".../system", so a
// claim like /run/systemd/transient(/.*)? with owned:true passed validation and
// would recursively relabel every transient unit. The list now mirrors
// `systemd-analyze unit-paths` from the verifier. (review finding)
func TestLoadRejectsAllSystemdUnitLoadDirs(t *testing.T) {
	tmpl := `name: widget
install: "true"
unit: widget.service
exercise: "true"
executables:
  - /opt/widget/bin/widgetd
paths:
  - { path: "%s(/.*)?", kind: conf, owned: true }
`
	// Every directory systemd loads units from must be refused even with owned:true.
	for _, dir := range []string{
		"/run/systemd/transient",
		"/run/systemd/system.control",
		"/etc/systemd/system.control",
		"/run/systemd/generator",
		"/run/systemd/generator.early",
		"/run/systemd/generator.late",
		"/etc/systemd/system.attached",
		"/run/systemd/system.attached",
		"/var/run/systemd/transient",
		"/run/user",
		// still-protected originals
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
	} {
		if _, err := Load(write(t, fmt.Sprintf(tmpl, dir))); err == nil {
			t.Errorf("claiming systemd unit-load dir %q must be rejected even with owned: true", dir)
		}
	}
	// A genuinely app-owned runtime dir is still allowed.
	if _, err := Load(write(t, fmt.Sprintf(tmpl, "/run/widget"))); err != nil {
		t.Errorf("a bounded app runtime dir must still load: %v", err)
	}
}
