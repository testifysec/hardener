// Package target defines the per-application manifest that drives the pipeline.
package target

import (
	"fmt"
	"os"
	"strings"

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
}

// isBroadSystemRoot reports whether root is a shared system tree (or "/").
func isBroadSystemRoot(root string) bool {
	root = strings.TrimRight(root, "/")
	return root == "" || broadSystemRoots[root]
}

// pathTiesToApp reports whether some component of root shares a meaningful
// prefix with the app name — the positive-ownership signal for a path claim.
func pathTiesToApp(root, appName string) bool {
	app := normPath(policy.SafeName(appName))
	need := 4
	if len(app) < need {
		need = len(app)
	}
	if need == 0 {
		return false
	}
	for _, seg := range strings.Split(root, "/") {
		if seg == "" {
			continue
		}
		if commonPrefixLen(normPath(seg), app) >= need {
			return true
		}
	}
	return false
}

func commonPrefixLen(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
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
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch t.Party {
	case "", "first", "second", "third":
	default:
		return nil, fmt.Errorf("%s: party must be first, second, or third (got %q)", path, t.Party)
	}
	if t.Party == "second" && t.Declared == nil {
		return nil, fmt.Errorf("%s: party: second requires a declared: block (the supplier's privilege declaration)", path)
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
		// file-context records (each fc line is newline-delimited) — reject them.
		if strings.ContainsAny(pa.Path, "\n\r\x00") {
			return nil, fmt.Errorf("%s: paths[%d]: path contains a newline or control character (file-context injection)", path, i)
		}
		root := literalRoot(pa.Path)
		if isBroadSystemRoot(root) {
			return nil, fmt.Errorf("%s: paths[%d] (%s): root %q is a broad system tree; declare a bounded, app-specific path", path, i, pa.Path, root)
		}
		// A path must be POSITIVELY app-owned, or a manifest could claim an
		// unrelated system file (/etc/passwd, /usr/lib64/libc.so.6) and have
		// %post restorecon relabel it (review finding). Ownership: some literal
		// component shares a meaningful prefix with the app name — loose enough
		// for vendor dirs (splunkforwarder for splunk-uf, plexmediaserver for
		// plex) yet rejecting unrelated system paths.
		if !pathTiesToApp(root, t.Name) {
			return nil, fmt.Errorf("%s: paths[%d] (%s): no path component ties to app %q — hardener will not relabel an unrelated system path; declare an app-owned location", path, i, pa.Path, t.Name)
		}
	}
	// Port proto/number are interpolated into root %post/%postun `semanage port`
	// commands, so an unvalidated protocol string could carry shell
	// metacharacters into install-time execution — and an unsupported protocol
	// is silently dropped from the TE socket rules (review finding). Constrain
	// them here: exactly tcp or udp, and a port in 1–65535.
	for i, po := range t.Ports {
		if po.Proto != "tcp" && po.Proto != "udp" {
			return nil, fmt.Errorf("%s: ports[%d]: protocol must be tcp or udp (got %q)", path, i, po.Proto)
		}
		if po.Port < 1 || po.Port > 65535 {
			return nil, fmt.Errorf("%s: ports[%d]: port must be 1–65535 (got %d)", path, i, po.Port)
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
