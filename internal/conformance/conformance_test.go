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
	if !reflectEq(obs.ForeignTypes, []string{"cert_t"}) {
		t.Errorf("foreign types: %v (must exclude own types and port types)", obs.ForeignTypes)
	}
	if !reflectEq(obs.ForeignPortBinds, []string{"http_cache_port_t"}) {
		t.Errorf("foreign port binds: %v", obs.ForeignPortBinds)
	}
	if len(obs.Ports) != 1 || obs.Ports[0].Port != 8443 {
		t.Errorf("ports: %v", obs.Ports)
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
