package pipeline

import (
	"testing"

	"github.com/testifysec/hardener/internal/policy"
)

func TestFCRoot(t *testing.T) {
	cases := map[string]string{
		"/var/lib/widget(/.*)?": "/var/lib/widget",
		"/etc/widget(/.*)?":     "/etc/widget",
		"/opt/widget/bin/w":     "/opt/widget/bin/w",
		"/var/log/w/.*":         "/var/log/w",
	}
	for in, want := range cases {
		if got := fcRoot(in); got != want {
			t.Errorf("fcRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMergeNewRulesIdempotent(t *testing.T) {
	var acc []policy.AllowRule
	r := policy.AllowRule{Source: "w_t", Target: "cert_t", Class: "file", Perms: []string{"read", "open"}}
	if n := mergeNewRules(&acc, []policy.AllowRule{r}); n != 1 {
		t.Fatalf("first merge: %d new, want 1", n)
	}
	if n := mergeNewRules(&acc, []policy.AllowRule{r}); n != 0 {
		t.Fatalf("second merge: %d new, want 0 (idempotent)", n)
	}
	// A new perm on the same target/class counts as new, then merges into one rule.
	r2 := policy.AllowRule{Source: "w_t", Target: "cert_t", Class: "file", Perms: []string{"getattr"}}
	if n := mergeNewRules(&acc, []policy.AllowRule{r2}); n != 1 {
		t.Fatalf("perm growth: want 1 new")
	}
	if len(acc) != 1 {
		t.Fatalf("normalize: want 1 merged rule, got %d: %+v", len(acc), acc)
	}
	if got := acc[0].Render(); got != "allow w_t cert_t:file { getattr open read };" {
		t.Errorf("merged render: %q", got)
	}
}
