package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

func spec73(t *testing.T) (spec, pre, post string) {
	t.Helper()
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	spec = GenerateSpec(p, "20260101000000")
	pre = spec[strings.Index(spec, "\n%pre\n"):]
	pre = pre[:strings.Index(pre, "\n%post\n")]
	post = spec[strings.Index(spec, "\n%post\n"):]
	post = post[:strings.Index(post, "\n%postun\n")]
	return
}
