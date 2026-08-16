package target

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
