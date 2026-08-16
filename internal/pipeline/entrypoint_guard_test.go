package pipeline

import (
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

func prof(name string, execs []string, paths ...string) *profile.Profile {
	p := &profile.Profile{Name: name, Executables: execs}
	for _, pa := range paths {
		p.Paths = append(p.Paths, profile.PathAccess{Path: pa, Kind: "content"})
	}
	return p
}

// Shared runtimes in system bin dirs must never be adopted as an app
// entrypoint — a positive app tie is required, not merely "not blacklisted".
// Versioned interpreters (python3.11) count as shared.
func TestSharedInterpretersAreNeverEntrypoints(t *testing.T) {
	p := prof("myapp", nil)
	for _, bad := range []string{
		"/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash",
		"/usr/bin/env", "/usr/bin/perl", "/usr/bin/python3", "/usr/bin/python3.11",
		"/usr/bin/node", "/usr/bin/ruby", "/usr/bin/java",
	} {
		if isAppOwnedExecutable(p, bad) {
			t.Errorf("%s must never be an app entrypoint", bad)
		}
	}
}

// Unrelated binaries — in a system bin dir OR a shared libexec/loader path —
// must never be adopted. Requires a positive app tie, not merely "not in a
// listed system bin dir" (that fallback let /usr/libexec/platform-python and
// /lib64/ld-linux-*.so.* through).
func TestUnrelatedBinariesAreNotEntrypoints(t *testing.T) {
	p := prof("myapp", nil)
	for _, bad := range []string{
		"/usr/bin/postgres",
		"/usr/libexec/platform-python3.9",
		"/lib64/ld-linux-x86-64.so.2",
		"/usr/libexec/other-daemon/helper",
		"/opt/somethingelse/bin/tool",
	} {
		if isAppOwnedExecutable(p, bad) {
			t.Errorf("%s is not myapp's entrypoint", bad)
		}
	}
}

// The reverse-substring check let a short basename that happens to be a
// substring of the app name pass: app "plex" would adopt /usr/bin/x because
// "plex" contains "x". Require an exact app-specific component, not substring.
func TestShortBasenameSubstringRejected(t *testing.T) {
	p := prof("plex", nil)
	for _, bad := range []string{"/usr/bin/x", "/usr/bin/le", "/usr/sbin/p"} {
		if isAppOwnedExecutable(p, bad) {
			t.Errorf("%s must not be adopted for app plex (reverse-substring hole)", bad)
		}
	}
	// The real plex binary, declared, is still fine.
	p2 := prof("plex", []string{"/usr/lib/plexmediaserver/Plex Media Server"})
	if !isAppOwnedExecutable(p2, "/usr/lib/plexmediaserver/Plex Media Server") {
		t.Error("declared plex binary must remain app-owned")
	}
}

// Positive ties: declared executables, app-claimed trees, private app dirs,
// and app-named binaries directly in a system bin dir.
func TestAppOwnedExecutablesAreEntrypoints(t *testing.T) {
	cases := []struct {
		app  string
		path string
		p    *profile.Profile
	}{
		{"emby", "/opt/emby-server/bin/emby-server", prof("emby", nil)},
		{"nats-server", "/usr/bin/nats-server", prof("nats-server", nil)},
		{"gitea", "/opt/gitea/bin/gitea", prof("gitea", nil)},
		// Plex's vendor dir has no separator boundary to "plex", so it relies
		// on the manifest declaring the executable (as plex.yaml does).
		{"plex", "/usr/lib/plexmediaserver/Plex Media Server", prof("plex", []string{"/usr/lib/plexmediaserver/Plex Media Server"})},
		{"webmin", "/usr/libexec/webmin/miniserv.pl", prof("webmin", nil)},
		{"mosquitto", "/usr/sbin/mosquitto", prof("mosquitto", nil)},
		{"declared", "/weird/path/thing", prof("declared", []string{"/weird/path/thing"})},
		{"claimed", "/srv/claimed/run", prof("claimed", nil, "/srv/claimed(/.*)?")},
	}
	for _, c := range cases {
		if !isAppOwnedExecutable(c.p, c.path) {
			t.Errorf("%s: %s should be an app-owned entrypoint", c.app, c.path)
		}
	}
}

// The forward prefix must be boundary-aware: app "post" must NOT adopt
// "postgres", nor "plex" adopt "plexiglass". Only exact, or app-name +
// separator (emby -> emby-server), qualifies.
func TestPrefixTieIsBoundaryAware(t *testing.T) {
	for _, c := range []struct {
		app, path string
	}{
		{"post", "/usr/bin/postgres"},
		{"plex", "/usr/bin/plexiglass"},
		{"nat", "/usr/bin/national"},
	} {
		if isAppOwnedExecutable(prof(c.app, nil), c.path) {
			t.Errorf("app %q must not adopt %q (boundary)", c.app, c.path)
		}
	}
	// Legitimate separator ties still hold.
	if !isAppOwnedExecutable(prof("emby", nil), "/opt/emby-server/bin/emby-server") {
		t.Error("emby-server must tie to app emby via separator")
	}
}

// Round 22: a declared path in a SHARED system bin dir must NOT be app-owned by
// declaration alone — that would relabel a shared binary (/usr/bin/curl) into
// the app domain. Ownership there must come from an app-name tie.
func TestDeclaredSharedBinNotOwned(t *testing.T) {
	for _, bad := range []string{"/usr/bin/curl", "/bin/tar", "/usr/sbin/nginx", "/usr/local/bin/helper"} {
		if isAppOwnedExecutable(prof("myapp", []string{bad}), bad) {
			t.Errorf("declaring %s must not make it app-owned (shared bin dir)", bad)
		}
	}
	// An app-NAMED binary in a shared bin dir stays owned via the name tie.
	if !isAppOwnedExecutable(prof("nats-server", nil), "/usr/bin/nats-server") {
		t.Error("app-named binary in /usr/bin must remain owned via the name tie")
	}
	// A declared VENDOR-dir path is still owned by declaration.
	if !isAppOwnedExecutable(prof("plex", []string{"/usr/lib/plexmediaserver/Plex Media Server"}), "/usr/lib/plexmediaserver/Plex Media Server") {
		t.Error("declared vendor-dir binary must remain owned")
	}
}
