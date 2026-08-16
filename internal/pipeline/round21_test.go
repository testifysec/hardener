package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

// Round 21 (#4): the %post FRESH-install rollback must restore base file labels
// after removing the module — the files were relabeled to now-undefined app
// types and would be inaccessible otherwise.
func TestSpecPostRollbackRestoresLabels(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget", Kind: "var_lib"}},
	}
	spec := GenerateSpec(p, "1")
	post := spec[strings.Index(spec, "%post"):strings.Index(spec, "%postun")]
	if !strings.Contains(post, "could not restore") {
		t.Errorf("%%post rollback must restore base labels after semodule -r:\n%s", post)
	}
}

// Round 21 (#5): stale port pruning on upgrade must FAIL CLOSED, not warn — a
// surviving <app>_port_t mapping keeps undeclared bind privilege.
func TestSpecPortPruneFailsClosed(t *testing.T) {
	p := &profile.Profile{Name: "widget", Ports: []profile.Port{{Proto: "tcp", Port: 8443}}}
	spec := GenerateSpec(p, "1")
	if !strings.Contains(spec, "refusing to leave an undeclared bind privilege") {
		t.Errorf("stale port pruning must fail closed:\n%s", spec)
	}
}
