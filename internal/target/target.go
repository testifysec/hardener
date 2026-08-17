// Package target defines the per-application manifest that drives the pipeline.
package target

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
)

// Target describes how to obtain, run, and exercise one application in the VM.
type Target struct {
	Name    string `yaml:"name"`
	License string `yaml:"license"` // open-source | proprietary-freely-distributable
	Source  string `yaml:"source"`  // where the artifact comes from (URL / repo)

	// Install is a bash script (run with sudo available) that installs the app.
	Install string `yaml:"install"`
	// Unit is the systemd unit name used to start/stop the app.
	Unit string `yaml:"unit"`
	// UnitFile, when set, is written to /etc/systemd/system/<Unit> before start
	// (for tarball/binary apps that ship no unit).
	UnitFile string `yaml:"unit_file,omitempty"`
	// Setup runs after install and unit placement (users, dirs, config).
	Setup string `yaml:"setup,omitempty"`
	// Exercise is a bash script that drives the app through its scenarios.
	Exercise string `yaml:"exercise"`

	Executables []string             `yaml:"executables"`
	Paths       []profile.PathAccess `yaml:"paths"`
	Ports       []profile.Port       `yaml:"ports,omitempty"`

	// Party is the supply-chain class of the artifact: "first" (our code,
	// baseline-checked), "second" (supplier deliverable, declaration-checked),
	// or "third" (COTS/OSS artifact, observation only). Empty means third.
	Party string `yaml:"party,omitempty"`
	// Declared is the supplier's claimed privilege set (second party).
	Declared *profile.Declaration `yaml:"declared,omitempty"`
	// Baseline is the path to the committed privilege baseline (first party).
	// Defaults to baselines/<name>.yaml relative to the manifest.
	Baseline string `yaml:"baseline,omitempty"`
}

// literalRoot returns the literal path prefix of a file-context regex — the
// part before the first regex metacharacter — which is the tree `restorecon -RF`
// would actually walk.
func literalRoot(expr string) string {
	for i, r := range expr {
		if strings.ContainsRune(`(.*+?[]{}^$|\`, r) {
			return strings.TrimRight(expr[:i], "/")
		}
	}
	return strings.TrimRight(expr, "/")
}

// broadSystemRoots are shared trees a manifest must never claim wholesale — a
// relabel of any of them would rewrite unrelated system files.
var broadSystemRoots = map[string]bool{
	"": true, "/usr": true, "/etc": true, "/var": true, "/bin": true,
	"/sbin": true, "/opt": true, "/lib": true, "/lib64": true, "/run": true,
	"/home": true, "/root": true, "/boot": true, "/dev": true, "/proc": true,
	"/sys": true, "/tmp": true, "/srv": true, "/mnt": true, "/media": true,
	"/usr/bin": true, "/usr/sbin": true, "/usr/lib": true, "/usr/lib64": true,
	"/usr/local": true, "/usr/share": true, "/usr/libexec": true,
	"/usr/local/bin": true, "/usr/local/sbin": true, "/usr/local/lib": true,
	"/var/lib": true, "/var/log": true, "/var/run": true, "/var/cache": true,
	"/var/tmp": true, "/etc/systemd": true, "/usr/lib/systemd": true,
	// Shared /var trees that hold OTHER services' data (mail/cron/at spools, web
	// roots, add-on packages, lock files). Claiming one wholesale with owned:true
	// would relabel unrelated data; an app owns a bounded subdir (/var/spool/myapp),
	// never the parent (review finding).
	"/var/spool": true, "/var/mail": true, "/var/www": true, "/var/opt": true,
	"/var/lock": true, "/var/local": true,
}

// sharedSystemdTrees are the unit directories that hold EVERY service's unit
// files. No manifest may claim them or anything under them — a recursive relabel
// would rewrite all units on the host — and the exact-match broadSystemRoots
// denylist could not enumerate every depth (review finding). Checked by prefix.
// The list below is systemd's OWN unit-load path, taken from `systemd-analyze
// unit-paths` (and `--user`) on the verifier rather than guessed. Enumerating only
// the ".../system" and ".../user" directories missed the SIBLING load
// directories — /run/systemd/transient, /run/systemd/system.control,
// /etc/systemd/system.control, the generator trees, the .attached trees — none of
// which are under or above ".../system", so a claim like
// /run/systemd/transient(/.*)? with owned:true passed validation and would
// recursively relabel every transient unit (review finding — round 78).
var sharedSystemdTrees = []string{
	"/etc/systemd/system", "/etc/systemd/user",
	"/usr/lib/systemd/system", "/usr/lib/systemd/user",
	// /usr/local/lib/systemd is the local-admin tier of systemd's unit load
	// path (higher priority than /usr/lib); packages and admins drop units
	// here, so it is as shared as /usr/lib and must not be claimable either
	// (review finding).
	"/usr/local/lib/systemd/system", "/usr/local/lib/systemd/user",
	"/usr/share/systemd/user", "/usr/local/share/systemd/user",
	"/etc/xdg/systemd/user",
	"/lib/systemd/system", "/lib/systemd/user",
	"/run/systemd/system", "/run/systemd/user",
	// Sibling unit-load directories under the same parents. `.control` holds
	// runtime property drop-ins, `transient` holds systemd-run units, the
	// generator trees hold generated units, and `.attached` holds portable-service
	// units — all are loaded as units, so relabeling any of them rewrites units
	// that are not ours.
	"/etc/systemd/system.control", "/run/systemd/system.control",
	"/run/systemd/user.control",
	"/run/systemd/transient",
	"/run/systemd/generator", "/run/systemd/generator.early", "/run/systemd/generator.late",
	"/etc/systemd/system.attached", "/run/systemd/system.attached",
	// Per-user runtime managers live under /run/user/<uid>/systemd; the whole
	// tree is systemd's, never an app's.
	"/run/user",
	// On RHEL /var/run is a symlink to /run, so a claim spelled with /var/run
	// must be rejected too — a path string can't resolve the symlink (review
	// finding).
	"/var/run/systemd/system", "/var/run/systemd/user",
	"/var/run/systemd/system.control", "/var/run/systemd/user.control",
	"/var/run/systemd/transient",
	"/var/run/systemd/generator", "/var/run/systemd/generator.early", "/var/run/systemd/generator.late",
	"/var/run/systemd/system.attached",
	"/var/run/user",
}

// isSharedSystemdTree reports whether root is, is UNDER, or is an ANCESTOR of a
// shared systemd unit directory. The ancestor case matters as much as the other
// two: a claim like /run/systemd(/.*)? or /usr/local/lib/systemd(/.*)? sits
// ABOVE a protected tree (/run/systemd/system, ...), so restorecon -RF on it
// would recursively relabel every shared unit beneath — the equal/descendant
// checks alone missed that (review finding).
func isSharedSystemdTree(root string) bool {
	root = strings.TrimRight(root, "/")
	for _, t := range sharedSystemdTrees {
		if root == t || strings.HasPrefix(root, t+"/") || strings.HasPrefix(t+"/", root+"/") {
			return true
		}
	}
	return isUserSystemdTree(root)
}

// userHomeBases are the roots under which per-user home directories live. A
// SYSTEM daemon's confined paths never belong inside a user's home, and every
// per-user systemd unit directory lives there — so claiming any of these (or
// anything under them) is refused outright. That also covers the per-user unit
// paths by construction, without having to enumerate usernames.
var userHomeBases = []string{"/home", "/root", "/var/home"}

// userSystemdSuffixes are systemd's per-user unit load-path tails. They are
// matched anywhere in the path so an unusual home location (/srv/people/bob,
// /export/home/bob) is covered too.
var userSystemdSuffixes = []string{
	"/.config/systemd", "/.local/share/systemd", "/.local/state/systemd",
	"/.config/environment.d",
}

// isUserSystemdTree reports whether root is, is under, or is an ancestor of a
// PER-USER systemd unit directory (/home/<user>/.config/systemd/user and friends).
// sharedSystemdTrees lists absolute paths and so could never cover these — the
// username sits in the middle — and a manifest NAMED after the user satisfied the
// ownership heuristic, so it could claim them without owned:true and recursively
// relabel every one of that user's units (review finding — round 80).
func isUserSystemdTree(root string) bool {
	root = strings.TrimRight(root, "/")
	// Any claim inside a home tree, or on the home tree itself.
	for _, b := range userHomeBases {
		if root == b || strings.HasPrefix(root, b+"/") || strings.HasPrefix(b+"/", root+"/") {
			return true
		}
	}
	// Per-user systemd dirs outside the standard home bases.
	for _, s := range userSystemdSuffixes {
		if strings.HasSuffix(root, s) || strings.Contains(root, s+"/") {
			return true
		}
	}
	return false
}

// isBroadSystemRoot reports whether root is a shared system tree (or "/").
func isBroadSystemRoot(root string) bool {
	root = strings.TrimRight(root, "/")
	return root == "" || broadSystemRoots[root] || isSharedSystemdTree(root)
}

// genericPathComponents are directory names too generic to prove app ownership
// on their own — a compound app name can start with one of them and falsely tie.
var genericPathComponents = map[string]bool{
	"system": true, "systemd": true, "etc": true, "usr": true, "var": true,
	"lib": true, "lib64": true, "bin": true, "sbin": true, "opt": true,
	"local": true, "share": true, "run": true, "srv": true, "home": true,
	"root": true, "boot": true, "dev": true, "proc": true, "sys": true,
	"tmp": true, "mnt": true, "media": true, "libexec": true, "cache": true,
	"log": true, "spool": true, "default": true, "config": true, "conf": true,
	"data": true, "www": true, "app": true, "apps": true, "service": true,
	"services": true, "daemon": true, "server": true,
}

// pathTiesToApp reports whether some component of root matches the app name at
// a TOKEN BOUNDARY — the positive-ownership signal for a path claim. A bare
// shared prefix is deliberately NOT enough: it let a short app name claim an
// unrelated tree (app "dock" → /var/lib/docker, app "a" → /etc/alternatives)
// because "docker" merely starts with "dock" (review finding). A component ties
// only when it equals the app name, or one is the other plus an underscore-
// delimited token (emby ↔ emby_server, nats_server ↔ nats). Vendor dirs whose
// name shares only a non-boundary prefix (plex ↔ plexmediaserver) cannot be
// confirmed syntactically and must carry an explicit `owned: true`.
func pathTiesToApp(root, appName string) bool {
	app := normPath(policy.SafeName(appName))
	if app == "" {
		return false
	}
	for _, seg := range strings.Split(root, "/") {
		seg = normPath(seg)
		if seg == "" {
			continue
		}
		// A GENERIC component never proves ownership on its own — not even an EXACT
		// match. An app literally named `services` must not claim /etc/services, and
		// `system-widget` must not claim /etc/systemd/system via the "system"
		// component (review finding). Any tie through a generic component requires
		// the explicit owned: true override.
		if genericPathComponents[seg] {
			continue
		}
		// App-specific component: exact, app-name+suffix (emby ↔ emby_server), or
		// the component is a prefix-token of a compound app name (nats ↔ nats_server).
		if seg == app || strings.HasPrefix(seg, app+"_") || strings.HasPrefix(app, seg+"_") {
			return true
		}
	}
	return false
}

// normPath lowercases and maps separators to underscores so path components
// compare against the SafeName-normalized app name.
func normPath(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

// Load reads and validates a target manifest.
func Load(path string) (*Target, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Target
	// Reject UNKNOWN fields. A silent-ignore decode turns a typo like
	// `partyy: second` into an empty Party — which defaults to third-party
	// handling, so failureOf no longer fails on undeclared behavior and the
	// artifact gets a passing attestation under weaker rules (review finding).
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Reject a MULTI-DOCUMENT manifest. Decoding stops at the first `---`, so a
	// second document (which could carry a different party/declaration) would be
	// silently ignored and the artifact evidenced under weaker rules (review
	// finding). A single document decodes, then the next Decode must be io.EOF.
	if err := dec.Decode(new(Target)); err != io.EOF {
		return nil, fmt.Errorf("%s: manifest must contain exactly one YAML document (content after '---' is not allowed)", path)
	}
	switch t.Party {
	case "", "first", "second", "third":
	default:
		return nil, fmt.Errorf("%s: party must be first, second, or third (got %q)", path, t.Party)
	}
	if t.Party == "second" && t.Declared == nil {
		return nil, fmt.Errorf("%s: party: second requires a declared: block (the supplier's privilege declaration)", path)
	}
	// A `declared:` block is ONLY meaningful for a second-party artifact, and a
	// `baseline:` only for first-party. Accepting either under an omitted/third
	// party would silently give a supplier weaker third-party handling (failureOf
	// only fails undeclared behavior for first/second) and a passing attestation
	// (review finding). Fail closed on the mismatch.
	if t.Declared != nil && t.Party != "second" {
		return nil, fmt.Errorf("%s: a declared: block is only valid for party: second (got party %q)", path, t.Party)
	}
	if t.Baseline != "" && t.Party != "first" {
		return nil, fmt.Errorf("%s: a baseline: is only valid for party: first (got party %q)", path, t.Party)
	}
	for _, missing := range []struct {
		ok  bool
		msg string
	}{
		{t.Name != "", "name"},
		{t.Install != "", "install"},
		{t.Unit != "", "unit"},
		{t.Exercise != "", "exercise"},
		{len(t.Executables) > 0, "executables"},
	} {
		if !missing.ok {
			return nil, fmt.Errorf("%s: missing required field %q", path, missing.msg)
		}
	}
	// Every declared path must name a KNOWN kind. An unknown or omitted kind
	// used to fall through to content silently, and content paths receive
	// can_exec — so a typo could make a config or state file executable. Fail
	// the manifest instead (review finding).
	for i, pa := range t.Paths {
		if pa.Path == "" {
			return nil, fmt.Errorf("%s: paths[%d]: missing path", path, i)
		}
		if !policy.KnownKind(pa.Kind) {
			return nil, fmt.Errorf("%s: paths[%d] (%s): unknown kind %q — must be one of conf, var_lib, log, runtime, content, tmp, cache, unit", path, i, pa.Path, pa.Kind)
		}
		// kind:exec in a PATH bypasses the app-ownership check that guards the
		// executables list — GenerateFC maps it straight to <app>_exec_t, so a
		// path like /usr/bin/curl could relabel a shared binary and route
		// unrelated launches into the domain (review finding). Entrypoints must
		// go through `executables`, which validates ownership.
		if pa.Kind == "exec" {
			return nil, fmt.Errorf("%s: paths[%d] (%s): kind 'exec' is not allowed in paths — declare entrypoints under 'executables' (which validates app ownership)", path, i, pa.Path)
		}
		// A path claim must be a BOUNDED, app-specific tree. GenerateFC emits it
		// as a file-context regex and %post runs `restorecon -RF` on its root, so
		// a broad claim like /usr(/.*)? or /(/.*)? would relabel large parts of
		// the customer filesystem — and exact collision detection does not catch
		// overlapping base-policy patterns (review finding). Reject any claim
		// whose literal root is a bare system directory.
		// A newline or control byte in a path lets a manifest inject additional
		// file-context records use WHITESPACE as field delimiters, so ANY space,
		// tab, newline, or control byte lets a value like "/etc/widget/config --"
		// split into a path plus an extra fc field/selector and relabel unintended
		// files (review finding). Reject all whitespace and control characters.
		if strings.ContainsFunc(pa.Path, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) {
			return nil, fmt.Errorf("%s: paths[%d]: path contains whitespace or a control character (file-context field injection)", path, i)
		}
		// Reject '%'. GenerateSpec interpolates this path into the RPM spec —
		// including %post scriptlet bodies and the HARDENER_ROOTS heredoc — and
		// rpmbuild expands %{...} and %(...) macros throughout the spec BEFORE the
		// shell runs. ShellQuote guards the shell, not rpmbuild, so a path like
		// /opt/plex%(id)/data would execute a command at build time or expand a
		// macro, making the signed RPM diverge from the verified policy. No
		// legitimate filesystem path contains '%' (review finding — round 64).
		if strings.ContainsRune(pa.Path, '%') {
			return nil, fmt.Errorf("%s: paths[%d] (%s): path contains '%%' — rpmbuild would macro-expand it in the generated spec; declare a path without '%%'", path, i, pa.Path)
		}
		// Reject path traversal. A regex like /etc/widget/../..(/.*)? passes the
		// textual ownership and broad-root checks, but its literal root
		// /etc/widget/../.. resolves through `restorecon -RF` to / and relabels
		// the whole host (review finding). A file-context root must be an
		// absolute path with no ".." component.
		if !strings.HasPrefix(pa.Path, "/") {
			return nil, fmt.Errorf("%s: paths[%d] (%s): path must be absolute", path, i, pa.Path)
		}
		for _, seg := range strings.Split(pa.Path, "/") {
			if seg == ".." {
				return nil, fmt.Errorf("%s: paths[%d] (%s): path traversal ('..') is not allowed — declare a bounded, canonical path", path, i, pa.Path)
			}
		}
		root := literalRoot(pa.Path)
		// Bounded grammar: the ONLY regex construct allowed is a single terminal
		// (/.*)?. A path is accepted only as a literal absolute path, or that path
		// plus (/.*)?. Otherwise an alternation like /etc/widget(/.*)?|/etc/shadow
		// passes the literal-root checks (root is /etc/widget) yet GenerateFC emits
		// the whole expression verbatim and restorecon relabels /etc/shadow via the
		// alternation (review finding).
		if pa.Path != root && pa.Path != root+"(/.*)?" {
			return nil, fmt.Errorf("%s: paths[%d] (%s): unsupported file-context expression — use a literal path optionally followed by a single terminal (/.*)?", path, i, pa.Path)
		}
		// The literal root must be CANONICAL. `/var//lib` is not in broadSystemRoots
		// (which lists `/var/lib`), but the kernel resolves the doubled slash and
		// `%post restorecon` would relabel the shared tree (review finding). Reject
		// any non-canonical root (`//`, `/./`, trailing `/`) so the broad-root and
		// ownership checks below see the path the kernel will actually walk.
		if filepath.Clean(root) != root {
			return nil, fmt.Errorf("%s: paths[%d] (%s): non-canonical path root %q (resolves to %q) — declare the canonical path", path, i, pa.Path, root, filepath.Clean(root))
		}
		if isBroadSystemRoot(root) {
			return nil, fmt.Errorf("%s: paths[%d] (%s): root %q is a broad system tree; declare a bounded, app-specific path", path, i, pa.Path, root)
		}
		// A path must be POSITIVELY app-owned, or a manifest could claim an
		// unrelated system file (/etc/passwd, /usr/lib64/libc.so.6) and have
		// %post restorecon relabel it (review finding). Ownership: some literal
		// component shares a meaningful prefix with the app name — loose enough
		// for vendor dirs (splunkforwarder for splunk-uf, plexmediaserver for
		// plex) yet rejecting unrelated system paths.
		if !pathTiesToApp(root, t.Name) && !pa.Owned {
			return nil, fmt.Errorf("%s: paths[%d] (%s): no path component ties to app %q at a token boundary — hardener will not relabel an unrelated system path. If this really is an app-owned vendor directory (e.g. plexmediaserver for plex), set `owned: true` on this path to vouch for it explicitly", path, i, pa.Path, t.Name)
		}
	}
	// Reject CONFLICTING in-profile file-context claims. GenerateFC would emit
	// overlapping entries with DIFFERENT types for the same path — the same regex
	// under two kinds, or an executable path repeated as a data/config path — and
	// semodule rejects a module with such a duplicate spec, failing the install
	// (review finding). Detect it at manifest load, not at install time.
	pathKind := map[string]string{}
	for i, pa := range t.Paths {
		if prev, ok := pathKind[pa.Path]; ok && prev != pa.Kind {
			return nil, fmt.Errorf("%s: paths[%d] (%s): declared twice with different kinds (%s and %s) — one path cannot carry two SELinux types", path, i, pa.Path, prev, pa.Kind)
		}
		pathKind[pa.Path] = pa.Kind
	}
	for i, exe := range t.Executables {
		if _, ok := pathKind[exe]; ok {
			return nil, fmt.Errorf("%s: executables[%d] (%s): also declared as a path — an executable takes the _exec_t type and cannot simultaneously carry a data/config type", path, i, exe)
		}
	}
	// Port proto/number are interpolated into root %post/%postun `semanage port`
	// commands, so an unvalidated protocol string could carry shell
	// metacharacters into install-time execution — and an unsupported protocol
	// is silently dropped from the TE socket rules (review finding). Constrain
	// them here: exactly tcp or udp, and a port in 1–65535.
	seenPort := map[string]bool{}
	for i, po := range t.Ports {
		if po.Proto != "tcp" && po.Proto != "udp" {
			return nil, fmt.Errorf("%s: ports[%d]: protocol must be tcp or udp (got %q)", path, i, po.Proto)
		}
		if po.Port < 1 || po.Port > 65535 {
			return nil, fmt.Errorf("%s: ports[%d]: port must be 1–65535 (got %d)", path, i, po.Port)
		}
		// Reject a DUPLICATE (proto, port). %postun captures the port listing ONCE
		// and tests every declared entry against that stale snapshot, so a duplicate
		// matches again after the first deletion already removed the mapping; the
		// second `semanage port -d` then fails, and the fail-closed handler aborts
		// %postun BEFORE `semodule -r` and the label restore — an RPM erase that
		// leaves the module and stale labels behind (review finding — round 70).
		// Reject at load rather than silently deduplicating: a repeated port is an
		// authoring error, and this keeps the deletion path strictly fail-closed.
		key := fmt.Sprintf("%s/%d", po.Proto, po.Port)
		if seenPort[key] {
			return nil, fmt.Errorf("%s: ports[%d]: duplicate port %d/%s — declare each protocol/port exactly once", path, i, po.Port, po.Proto)
		}
		seenPort[key] = true
	}
	// Every executable is relabeled as the app exec type and interpolated into
	// %post shell, so validate path-safety: absolute, canonical (no ".." or
	// non-canonical form), and free of newline/control bytes (review finding —
	// Load previously only checked the list was non-empty). Spaces ARE allowed
	// (vendor binaries like "Plex Media Server"). NOTE: this validates the path
	// shape, not app OWNERSHIP — an executable named after a system binary
	// (/usr/bin/curl) still needs the deferred package-ownership check; that
	// remains the pipeline's isAppOwnedExecutable guard plus the recorded design
	// decision.
	for i, exe := range t.Executables {
		if !strings.HasPrefix(exe, "/") {
			return nil, fmt.Errorf("%s: executables[%d] (%s): must be an absolute path", path, i, exe)
		}
		if strings.ContainsFunc(exe, unicode.IsControl) {
			return nil, fmt.Errorf("%s: executables[%d]: contains a control character (newline/tab/NUL)", path, i)
		}
		// Reject '%' for the same reason as paths: GenerateSpec interpolates each
		// executable into the %post scriptlet, and rpmbuild macro-expands %{...} and
		// %(...) before the shell runs. Spaces are allowed (vendor binaries like
		// "Plex Media Server") but '%' never appears in a legitimate binary path and
		// would let rpmbuild execute a command or expand a macro at build time,
		// diverging the signed RPM from the verified policy (review finding — round 64).
		if strings.ContainsRune(exe, '%') {
			return nil, fmt.Errorf("%s: executables[%d] (%s): contains '%%' — rpmbuild would macro-expand it in the generated %%post spec; declare a path without '%%'", path, i, exe)
		}
		if filepath.Clean(exe) != exe {
			return nil, fmt.Errorf("%s: executables[%d] (%s): non-canonical path (resolves to %q) — declare the canonical path", path, i, exe, filepath.Clean(exe))
		}
		for _, seg := range strings.Split(exe, "/") {
			if seg == ".." {
				return nil, fmt.Errorf("%s: executables[%d] (%s): path traversal ('..') is not allowed", path, i, exe)
			}
		}
	}
	return &t, nil
}

// Profile builds the initial security profile from the manifest.
func (t *Target) Profile() *profile.Profile {
	return &profile.Profile{
		Name:        t.Name,
		Executables: t.Executables,
		Paths:       t.Paths,
		Ports:       t.Ports,
	}
}
