package policy

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
)

func widgetProfile() *profile.Profile {
	return &profile.Profile{
		Name: "widget",
		Executables: []string{
			"/opt/widget/bin/widgetd",
		},
		Paths: []profile.PathAccess{
			{Path: "/etc/widget(/.*)?", Kind: "conf"},
			{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"},
			{Path: "/var/log/widget(/.*)?", Kind: "log"},
			{Path: "/run/widget(/.*)?", Kind: "runtime"},
			{Path: "/opt/widget/data(/.*)?", Kind: "content"},
		},
		Ports: []profile.Port{{Proto: "tcp", Port: 8443}},
	}
}

func TestGenerateTE(t *testing.T) {
	te := GenerateTE(widgetProfile())
	for _, want := range []string{
		"policy_module(widget",
		"type widget_t;",
		"type widget_exec_t;",
		"init_daemon_domain(widget_t, widget_exec_t)",
		"type widget_conf_t;",
		"type widget_var_lib_t;",
		"type widget_log_t;",
		"type widget_runtime_t;",
		"type widget_port_t;",
		"corenet_port(widget_port_t)",
		"allow widget_t widget_port_t:tcp_socket name_bind;",
		"logging_log_file(widget_log_t)",
	} {
		if !strings.Contains(te, want) {
			t.Errorf("TE missing %q\n---\n%s", want, te)
		}
	}
	// The generator must never emit blanket escape hatches.
	for _, banned := range []string{"permissive widget_t", "unconfined_domain", "allow widget_t self:capability *"} {
		if strings.Contains(te, banned) {
			t.Errorf("TE contains banned construct %q", banned)
		}
	}
}

func TestGenerateFC(t *testing.T) {
	fc := GenerateFC(widgetProfile())
	for _, want := range []string{
		`/opt/widget/bin/widgetd	--	gen_context(system_u:object_r:widget_exec_t,s0)`,
		`/etc/widget(/.*)?	gen_context(system_u:object_r:widget_conf_t,s0)`,
		`/var/lib/widget(/.*)?	gen_context(system_u:object_r:widget_var_lib_t,s0)`,
		`/var/log/widget(/.*)?	gen_context(system_u:object_r:widget_log_t,s0)`,
		`/run/widget(/.*)?	gen_context(system_u:object_r:widget_runtime_t,s0)`,
	} {
		if !strings.Contains(fc, want) {
			t.Errorf("FC missing %q\n---\n%s", want, fc)
		}
	}
}

// Multiple ports of the same protocol share one port type, so the name_bind
// rule must be emitted once — duplicates are noise in a security artifact
// that humans are expected to review.
func TestGenerateTEDeduplicatesPortRules(t *testing.T) {
	p := widgetProfile()
	p.Ports = []profile.Port{
		{Proto: "tcp", Port: 4222},
		{Proto: "tcp", Port: 8222},
		{Proto: "udp", Port: 9999},
	}
	te := GenerateTE(p)
	if n := strings.Count(te, "allow widget_t widget_port_t:tcp_socket name_bind;"); n != 1 {
		t.Errorf("tcp name_bind emitted %d times, want 1:\n%s", n, te)
	}
	if n := strings.Count(te, "allow widget_t widget_port_t:udp_socket name_bind;"); n != 1 {
		t.Errorf("udp name_bind emitted %d times, want 1", n)
	}
}

// FC regexes contain characters that need escaping in literal path segments.
func TestFCEscapesRegexMeta(t *testing.T) {
	p := &profile.Profile{
		Name:        "plex",
		Executables: []string{"/usr/lib/plexmediaserver/Plex Media Server"},
	}
	fc := GenerateFC(p)
	if !strings.Contains(fc, `/usr/lib/plexmediaserver/Plex\sMedia\sServer`) {
		t.Errorf("FC does not escape spaces:\n%s", fc)
	}
	if strings.Contains(fc, "Plex Media Server\t") || strings.Contains(fc, "[ ]") {
		t.Errorf("literal space or [ ] must never reach an fc line:\n%s", fc)
	}
}

// Round 42: capability2 caps (bpf/perfmon) must be emitted under self:capability2,
// not self:capability, or the module fails to compile.
func TestCapabilitiesPartitionedByClass(t *testing.T) {
	p := &profile.Profile{Name: "widget", Capabilities: []string{"net_bind_service", "bpf", "perfmon"}}
	te := GenerateTE(p)
	if !strings.Contains(te, "self:capability { net_bind_service }") && !strings.Contains(te, "self:capability {net_bind_service}") {
		t.Errorf("v1 capability must stay under self:capability:\n%s", te)
	}
	if !strings.Contains(te, "self:capability2 {") || !strings.Contains(te, "bpf") || !strings.Contains(te, "perfmon") {
		t.Errorf("capability2 caps must be emitted under self:capability2:\n%s", te)
	}
	if strings.Contains(te, "self:capability { net_bind_service bpf perfmon }") {
		t.Error("capability2 caps must NOT be emitted under self:capability")
	}
}

// Round 42: cert_t must not be granted by a base interface (it would suppress the
// review AVC for TLS private keys).
func TestBaseInterfacesOmitGenericCertRead(t *testing.T) {
	for _, iface := range BaseInterfaces {
		if iface == "miscfiles_read_generic_certs" {
			t.Error("miscfiles_read_generic_certs must not be a base grant (defeats cert_t review)")
		}
	}
}

// Round 72: KindCache received the manage_* patterns but NO type transition,
// unlike every sibling kind. /var/cache is var_t and RPM install skips a root
// that does not exist yet, so an app creating its own cache directory on first
// start had it labeled var_t instead of <app>_cache_t — denied, and unable to
// converge in the field. The transition is name-scoped to the declared cache
// root's leaf so it does not claim everything the domain creates under var_t.
// (Interface arity and the emitted rule were compile-verified on the verifier:
// `type_transition widget_t var_t:dir widget_cache_t widget;`)
func TestGenerateTEEmitsCacheFileTransition(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/cache/widget(/.*)?", Kind: "cache"}},
	}
	te := GenerateTE(p)
	want := `files_var_filetrans(widget_t, widget_cache_t, { dir file }, "widget")`
	if !strings.Contains(te, want) {
		t.Errorf("cache kind must emit a name-scoped var filetrans; missing %q in:\n%s", want, te)
	}
	// A profile with no cache path must not emit one.
	p2 := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	if strings.Contains(GenerateTE(p2), "files_var_filetrans") {
		t.Error("a profile without a cache path must not emit a var filetrans")
	}
}

// The transition name is the declared cache root's leaf directory, deduplicated,
// and never carries characters that would escape the .te string literal.
func TestCacheTransitionNames(t *testing.T) {
	p := &profile.Profile{Paths: []profile.PathAccess{
		{Path: "/var/cache/widget(/.*)?", Kind: "cache"},
		{Path: "/var/cache/widget2", Kind: "cache"},
		{Path: "/var/cache/widget(/.*)?", Kind: "cache"}, // duplicate leaf
		{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}, // not a cache path
	}}
	got := cacheTransitionNames(p)
	want := []string{"widget", "widget2"}
	if len(got) != len(want) {
		t.Fatalf("cacheTransitionNames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cacheTransitionNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
