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
		{"plex", "/usr/lib/plexmediaserver/Plex Media Server", prof("plex", nil)},
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
