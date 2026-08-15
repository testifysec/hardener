package policy

import (
	"strings"
	"testing"
)

// Refined rules referencing types foreign to the module need a gen_require
// block; our own declared types must not appear in it.
func TestRenderRefinedSection(t *testing.T) {
	p := widgetProfile()
	rules := []AllowRule{
		{Source: "widget_t", Target: "cert_t", Class: "file", Perms: []string{"read"}},
		{Source: "widget_t", Target: "widget_var_lib_t", Class: "file", Perms: []string{"lock"}},
		{Source: "widget_t", Target: "widget_t", Class: "process", Perms: []string{"setrlimit"}},
		{Source: "widget_t", Target: "http_port_t", Class: "tcp_socket", Perms: []string{"name_bind"}},
	}
	out := RenderRefinedSection(p, rules)
	if !strings.Contains(out, "gen_require(`") {
		t.Fatalf("missing gen_require:\n%s", out)
	}
	for _, want := range []string{"type cert_t;", "type http_port_t;"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing require %q:\n%s", want, out)
		}
	}
	for _, banned := range []string{"type widget_var_lib_t;", "type widget_t;"} {
		if strings.Contains(out, banned) {
			t.Errorf("own type %q must not be required:\n%s", banned, out)
		}
	}
	if !strings.Contains(out, "allow widget_t widget_t:process setrlimit;") {
		t.Errorf("self rule missing:\n%s", out)
	}
}
