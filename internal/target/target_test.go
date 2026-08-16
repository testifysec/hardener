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
	for _, ok := range []string{"conf", "var_lib", "log", "runtime", "content", "tmp", "cache", "unit", "exec"} {
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
	for _, ok := range []string{"/etc/widget(/.*)?", "/var/lib/widget(/.*)?", "/opt/widget(/.*)?", "/usr/lib/widgetsrv(/.*)?"} {
		if _, err := Load(write(t, fmt.Sprintf(broadPathManifest, ok))); err != nil {
			t.Errorf("bounded path %q must load: %v", ok, err)
		}
	}
}
