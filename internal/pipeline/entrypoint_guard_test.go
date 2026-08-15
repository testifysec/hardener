package pipeline

import "testing"

// Vendor units love ExecStart=/bin/sh -c '... exec "real-binary"'. Deriving
// the entrypoint from ExecStart must NEVER label a shared interpreter as the
// app's exec type: labeling /bin/sh plex_exec_t would make every shell
// invocation on the system transition into plex_t. The transition still
// happens on the exec of the real (labeled) binary inside the wrapper.
func TestSharedInterpretersAreNeverEntrypoints(t *testing.T) {
	for _, bad := range []string{
		"/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash",
		"/usr/bin/env", "/usr/bin/perl", "/usr/bin/python3", "/usr/bin/dash",
	} {
		if isEntrypointCandidate(bad) {
			t.Errorf("%s must never become an app entrypoint", bad)
		}
	}
}

func TestAppBinariesAreEntrypoints(t *testing.T) {
	for _, good := range []string{
		"/opt/emby-server/bin/emby-server", // app-owned sh wrapper: fine to label
		"/usr/bin/nats-server",
		"/usr/lib/plexmediaserver/Plex Media Server",
	} {
		if !isEntrypointCandidate(good) {
			t.Errorf("%s should be an entrypoint candidate", good)
		}
	}
}
