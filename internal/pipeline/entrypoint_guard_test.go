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
	// The real plex binary is owned via its declared PATH (rule 2), as plex.yaml
	// declares /usr/lib/plexmediaserver(/.*)? — declaration of the executable
	// alone is no longer sufficient.
	p2 := prof("plex", []string{"/usr/lib/plexmediaserver/Plex Media Server"}, "/usr/lib/plexmediaserver(/.*)?")
	if !isAppOwnedExecutable(p2, "/usr/lib/plexmediaserver/Plex Media Server") {
		t.Error("plex binary under its declared path must be app-owned")
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
		// Plex's vendor dir has no separator boundary to "plex", so ownership
		// comes from the declared PATH (rule 2), as plex.yaml declares it.
		{"plex", "/usr/lib/plexmediaserver/Plex Media Server", prof("plex", []string{"/usr/lib/plexmediaserver/Plex Media Server"}, "/usr/lib/plexmediaserver(/.*)?")},
		{"webmin", "/usr/libexec/webmin/miniserv.pl", prof("webmin", nil)},
		{"mosquitto", "/usr/sbin/mosquitto", prof("mosquitto", nil)},
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
	// A vendor-dir binary is owned via the declared PATH (rule 2), not by
	// declaring the executable alone (which is no longer sufficient anywhere).
	if !isAppOwnedExecutable(prof("plex", []string{"/usr/lib/plexmediaserver/Plex Media Server"}, "/usr/lib/plexmediaserver(/.*)?"), "/usr/lib/plexmediaserver/Plex Media Server") {
		t.Error("vendor-dir binary under a declared path must remain owned")
	}
	// Declaration ALONE — even outside a shared bin dir — is NOT ownership: a
	// declared shared system file must not be adopted (review finding).
	if isAppOwnedExecutable(prof("myapp", []string{"/usr/lib/systemd/system/sshd.service"}), "/usr/lib/systemd/system/sshd.service") {
		t.Error("declaring a shared system file must not confer app ownership")
	}
}
