package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
)

func widgetProfile() *profile.Profile {
	return &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths: []profile.PathAccess{
			{Path: "/etc/widget(/.*)?", Kind: "conf"},
			{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"},
		},
		Ports: []profile.Port{{Proto: "tcp", Port: 8443}},
	}
}

// Observed behavior is extracted from the profile plus the final refined rules.
func TestExtractObserved(t *testing.T) {
	rules := []policy.AllowRule{
		{Source: "widget_t", Target: "widget_t", Class: "capability", Perms: []string{"setgid", "setuid"}},
		{Source: "widget_t", Target: "cert_t", Class: "file", Perms: []string{"open", "read"}},
		{Source: "widget_t", Target: "http_cache_port_t", Class: "tcp_socket", Perms: []string{"name_bind"}},
		{Source: "widget_t", Target: "widget_var_lib_t", Class: "file", Perms: []string{"lock"}}, // own type: not foreign
	}
	obs := ExtractObserved(widgetProfile(), rules)
	if !reflectEq(obs.Capabilities, []string{"setgid", "setuid"}) {
		t.Errorf("capabilities: %v", obs.Capabilities)
	}
	if !reflectEq(obs.ForeignTypes, []string{"cert_t:file:open", "cert_t:file:read"}) {
		t.Errorf("foreign types: %v (type:class:perm, excluding own and port types)", obs.ForeignTypes)
	}
	if !reflectEq(obs.ForeignPortBinds, []string{"http_cache_port_t:tcp_socket:0"}) {
		t.Errorf("foreign port binds: %v", obs.ForeignPortBinds)
	}
	if len(obs.Ports) != 1 || obs.Ports[0].Port != 8443 {
		t.Errorf("ports: %v", obs.Ports)
	}
}

// Round 12, finding #3: a non-bind port permission (name_connect for outbound,
// recv/send) must NOT be silently dropped. Previously only name_bind was
// recorded from a *_port_t rule, so undeclared outbound access to http_port_t
// vanished from both ForeignPortBinds and ForeignTypes and passed second-party
// conformance — producing incorrect evidence.
func TestForeignPortConnectSurfacesAsForeignType(t *testing.T) {
	has := func(xs []string, v string) bool {
		for _, x := range xs {
			if x == v {
				return true
			}
		}
		return false
	}
	rules := []policy.AllowRule{
		{Source: "widget_t", Target: "http_port_t", Class: "tcp_socket", Perms: []string{"name_connect"}},
	}
	obs := ExtractObserved(widgetProfile(), rules)
	if !has(obs.ForeignTypes, "http_port_t:tcp_socket:name_connect") {
		t.Errorf("outbound name_connect to http_port_t must surface as a foreign type, got ForeignTypes=%v", obs.ForeignTypes)
	}
	if has(obs.ForeignPortBinds, "http_port_t") {
		t.Errorf("name_connect is not a bind and must not appear in ForeignPortBinds: %v", obs.ForeignPortBinds)
	}

	// A rule with BOTH name_bind and name_connect is recorded as both — the
	// bind faces ForeignPortBinds, the outbound faces ForeignTypes.
	both := ExtractObserved(widgetProfile(), []policy.AllowRule{
		{Source: "widget_t", Target: "dns_port_t", Class: "tcp_socket", Perms: []string{"name_bind", "name_connect"}},
	})
	if !has(both.ForeignPortBinds, "dns_port_t:tcp_socket:0") || !has(both.ForeignTypes, "dns_port_t:tcp_socket:name_connect") {
		t.Errorf("bind+connect must record both: binds=%v types=%v", both.ForeignPortBinds, both.ForeignTypes)
	}
}

// A supplier declaration that omits observed privileged behavior yields
// undeclared findings — the second-party contract violation signal.
func TestCompareFlagsUndeclared(t *testing.T) {
	decl := &profile.Declaration{
		Capabilities: []string{"setgid"}, // setuid NOT declared
		Ports:        []profile.Port{{Proto: "tcp", Port: 8443}},
		ForeignTypes: []string{"cert_t"},
	}
	obs := Observed{
		Capabilities:     []string{"setgid", "setuid"},
		Ports:            []profile.Port{{Proto: "tcp", Port: 8443}},
		ForeignTypes:     []string{"cert_t"},
		ForeignPortBinds: []string{"http_cache_port_t"},
	}
	rep := Compare(decl, obs)
	kinds := map[string]bool{}
	for _, f := range rep.Undeclared {
		kinds[f.Kind+":"+f.Item] = true
	}
	if !kinds["capability:setuid"] {
		t.Errorf("missing undeclared capability finding: %+v", rep.Undeclared)
	}
	if !kinds["port-bind:http_cache_port_t"] {
		t.Errorf("missing undeclared port-bind finding: %+v", rep.Undeclared)
	}
	if len(rep.Undeclared) != 2 {
		t.Errorf("want exactly 2 undeclared findings, got %+v", rep.Undeclared)
	}
}

// Declared-but-unobserved is a coverage/over-declaration warning, never fatal.
func TestCompareReportsUnexercised(t *testing.T) {
	decl := &profile.Declaration{
		Capabilities: []string{"setgid", "net_admin"},
		ForeignTypes: []string{"cert_t", "krb5_conf_t"},
	}
	obs := Observed{Capabilities: []string{"setgid"}, ForeignTypes: []string{"cert_t"}}
	rep := Compare(decl, obs)
	if len(rep.Undeclared) != 0 {
		t.Errorf("nothing undeclared here, got %+v", rep.Undeclared)
	}
	joined := strings.Join(rep.Unexercised, " ")
	if !strings.Contains(joined, "net_admin") || !strings.Contains(joined, "krb5_conf_t") {
		t.Errorf("unexercised: %v", rep.Unexercised)
	}
}

// Exact match: clean report both directions.
func TestCompareCleanMatch(t *testing.T) {
	decl := &profile.Declaration{
		Capabilities: []string{"setgid"},
		Ports:        []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	obs := Observed{Capabilities: []string{"setgid"}, Ports: []profile.Port{{Proto: "tcp", Port: 8443}}}
	rep := Compare(decl, obs)
	if len(rep.Undeclared)+len(rep.Unexercised) != 0 {
		t.Errorf("expected clean, got %+v", rep)
	}
}

// Verdict semantics per party class.
func TestVerdictByParty(t *testing.T) {
	dirty := Report{Undeclared: []Finding{{Kind: "capability", Item: "setuid", Severity: "high"}}}
	clean := Report{}

	cases := []struct {
		party  string
		report Report
		fatal  bool
	}{
		{"third", dirty, false}, // advisory only: no declaration contract exists
		{"second", dirty, true}, // supplier violated its declaration
		{"second", clean, false},
		{"first", dirty, true}, // drift from committed baseline
		{"first", clean, false},
	}
	for _, c := range cases {
		fatal, reason := Verdict(c.party, c.report)
		if fatal != c.fatal {
			t.Errorf("party=%s dirty=%v: fatal=%v (%s), want %v", c.party, len(c.report.Undeclared) > 0, fatal, reason, c.fatal)
		}
		if fatal && reason == "" {
			t.Errorf("party=%s: fatal verdict must carry a reason", c.party)
		}
	}
}

// First-party baselines round-trip through YAML: save observed, load, compare clean.
func TestBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "widget-baseline.yaml")
	obs := Observed{
		Capabilities:     []string{"setgid", "setuid"},
		Ports:            []profile.Port{{Proto: "tcp", Port: 8443}},
		ForeignTypes:     []string{"cert_t"},
		ForeignPortBinds: []string{"http_cache_port_t"},
	}
	if err := SaveBaseline(path, obs); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	decl, err := LoadDeclaration(path)
	if err != nil {
		t.Fatalf("LoadDeclaration: %v", err)
	}
	rep := Compare(decl, obs)
	if len(rep.Undeclared)+len(rep.Unexercised) != 0 {
		t.Errorf("round-trip must compare clean, got %+v", rep)
	}
	// Drift: new capability appears after baseline was frozen.
	obs.Capabilities = append(obs.Capabilities, "net_raw")
	rep = Compare(decl, obs)
	if len(rep.Undeclared) != 1 || rep.Undeclared[0].Item != "net_raw" {
		t.Errorf("drift not detected: %+v", rep.Undeclared)
	}
}

func TestLoadDeclarationMissingFile(t *testing.T) {
	if _, err := LoadDeclaration(filepath.Join(t.TempDir(), "nope.yaml")); !os.IsNotExist(err) {
		t.Errorf("want os.IsNotExist, got %v", err)
	}
}

func reflectEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Round 21: conformance keys foreign access at type:class:PERMISSION, so a
// declared READ of cert_t does not silently permit a new WRITE (escalation),
// while using LESS than declared stays clean.
func TestForeignAccessEscalationFlagged(t *testing.T) {
	decl := &profile.Declaration{ForeignTypes: []string{"cert_t:file:read", "cert_t:file:open"}}
	esc := Compare(decl, Observed{ForeignTypes: []string{"cert_t:file:open", "cert_t:file:read", "cert_t:file:write"}})
	if len(esc.Undeclared) != 1 || esc.Undeclared[0].Item != "cert_t:file:write" {
		t.Errorf("an undeclared cert_t write must be flagged as escalation, got %+v", esc.Undeclared)
	}
	sub := Compare(decl, Observed{ForeignTypes: []string{"cert_t:file:read"}})
	if len(sub.Undeclared) != 0 {
		t.Errorf("using less than declared must not be an undeclared finding: %+v", sub.Undeclared)
	}
}

// Round 25: a tcp_socket name_bind and a udp_socket name_bind on the SAME
// *_port_t must be DISTINCT observed binds — keying by target type alone let an
// added UDP bind collapse into an existing TCP one, so drift/undeclared use
// passed on identical baselines (review finding).
func TestBindKeyDistinguishesProtocol(t *testing.T) {
	p := &profile.Profile{Name: "widget"}
	rules := []policy.AllowRule{
		{Source: "widget_t", Target: "dns_port_t", Class: "tcp_socket", Perms: []string{"name_bind"}, Port: 53},
		{Source: "widget_t", Target: "dns_port_t", Class: "udp_socket", Perms: []string{"name_bind"}, Port: 53},
	}
	obs := ExtractObserved(p, rules)
	got := strings.Join(obs.ForeignPortBinds, ",")
	if !strings.Contains(got, "dns_port_t:tcp_socket:53") || !strings.Contains(got, "dns_port_t:udp_socket:53") {
		t.Fatalf("tcp and udp binds must be distinct entries, got %v", obs.ForeignPortBinds)
	}
	// A declaration that only permits the TCP bind must flag the UDP bind as
	// undeclared, not silently absorb it.
	decl := &profile.Declaration{ForeignPortBinds: []string{"dns_port_t:tcp_socket:53"}}
	rep := Compare(decl, obs)
	found := false
	for _, f := range rep.Undeclared {
		if f.Kind == "port-bind" && f.Item == "dns_port_t:udp_socket:53" {
			found = true
		}
	}
	if !found {
		t.Errorf("undeclared udp bind must be flagged, got %+v", rep.Undeclared)
	}
}

// Round 61: two binds with the SAME SELinux port type and socket class but
// DIFFERENT numeric ports must be distinct observations — keying by type:class
// alone let a new bind on another port sharing unreserved_port_t collapse into
// an existing declaration and pass as clean supply-chain evidence.
func TestBindKeyDistinguishesPort(t *testing.T) {
	p := &profile.Profile{Name: "widget"}
	rules := []policy.AllowRule{
		{Source: "widget_t", Target: "unreserved_port_t", Class: "tcp_socket", Perms: []string{"name_bind"}, Port: 8080},
		{Source: "widget_t", Target: "unreserved_port_t", Class: "tcp_socket", Perms: []string{"name_bind"}, Port: 9090},
	}
	obs := ExtractObserved(p, rules)
	if len(obs.ForeignPortBinds) != 2 {
		t.Fatalf("two different ports on the same type/class must be two entries, got %v", obs.ForeignPortBinds)
	}
	// Declaring only the 8080 bind must flag the 9090 bind, not absorb it.
	decl := &profile.Declaration{ForeignPortBinds: []string{"unreserved_port_t:tcp_socket:8080"}}
	rep := Compare(decl, obs)
	found := false
	for _, f := range rep.Undeclared {
		if f.Kind == "port-bind" && f.Item == "unreserved_port_t:tcp_socket:9090" {
			found = true
		}
	}
	if !found {
		t.Errorf("a new bind on another port sharing the type must be flagged undeclared, got %+v", rep.Undeclared)
	}
}

// Round 38: the first-party caddy baseline must declare the SAME base_grants the
// generated domain unconditionally receives (policy.BaseInterfaces), or the
// unchanged party-first-caddy target reports drift and fails. This keeps the
// committed baseline in sync if BaseInterfaces ever changes.
func TestCaddyBaselineDeclaresBaseGrants(t *testing.T) {
	decl, err := LoadDeclaration("../../targets/baselines/caddy.yaml")
	if err != nil {
		t.Fatalf("load caddy baseline: %v", err)
	}
	got := toSet(decl.BaseGrants)
	for _, g := range policy.BaseInterfaces {
		if !got[g] {
			t.Errorf("caddy baseline is missing base grant %q (declared %v)", g, decl.BaseGrants)
		}
	}
	if len(decl.BaseGrants) != len(policy.BaseInterfaces) {
		t.Errorf("caddy baseline base_grants count %d != BaseInterfaces %d", len(decl.BaseGrants), len(policy.BaseInterfaces))
	}
}
