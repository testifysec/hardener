package pipeline

import (
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

func spec79(t *testing.T) string {
	t.Helper()
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	return GenerateSpec(p, "20260101000000")
}
