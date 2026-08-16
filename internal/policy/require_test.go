package policy

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
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

// ownTypes must own EXACTLY what GenerateTE declares: dom + exec always, a kind
// type only when a path of that kind exists, the port type only when ports are
// declared. Over-marking let an externally defined same-name type (a foreign
// widget_port_t when the profile has no ports) bypass foreign-type review while
// its declaration was omitted from the module. (review finding — round 51)
func TestOwnTypesMatchesGeneratedTypes(t *testing.T) {
	// A minimal profile: one var_lib path, NO ports, NO conf/content/tmp/cache.
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	own := ownTypes(p)
	for _, want := range []string{"widget_t", "widget_exec_t", "widget_var_lib_t"} {
		if !own[want] {
			t.Errorf("%s must be owned", want)
		}
	}
	// No ports declared → the port type is NOT ours; a foreign widget_port_t must
	// reach foreign-type review, not be silently treated as owned.
	if own[PortType(p.Name)] {
		t.Errorf("%s must NOT be owned when the profile declares no ports", PortType(p.Name))
	}
	for _, notOwned := range []string{"widget_conf_t", "widget_content_t", "widget_tmp_t", "widget_cache_t", "widget_log_t"} {
		if own[notOwned] {
			t.Errorf("%s must NOT be owned — no matching path kind declared", notOwned)
		}
	}
}
