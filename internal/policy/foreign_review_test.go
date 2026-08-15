package policy

import (
	"testing"

	"github.com/testifysec/hardener/internal/avc"
)

// Foreign-type access defaults to review: a type that is neither ours nor on
// the safe allowlist must be flagged, not silently auto-applied. A blocklist
// failed open — an attempted read of ssh_home_t would just become policy.
func TestUnknownForeignTypeFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "ssh_home_t", Class: "file",
		Perms: []string{"read"}, Path: "/home/x/.ssh/id_rsa",
	}}
	res := Refine(p, ds)
	if len(res.Flags) != 1 {
		t.Fatalf("unknown foreign type must be flagged, got %+v", res)
	}
	if len(res.AllowRules) != 0 {
		t.Errorf("flagged foreign access must not auto-apply: %v", res.AllowRules)
	}
}

// A curated safe foreign type (cert_t) is allowed without a flag.
func TestSafeForeignTypeNotFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "cert_t", Class: "file",
		Perms: []string{"read", "open"}, Path: "/etc/pki/tls/cert.pem",
	}}
	if res := Refine(p, ds); len(res.Flags) != 0 {
		t.Errorf("cert_t is safe and must not be flagged: %+v", res.Flags)
	}
}

// The app's own types are never flagged (they are the point of the policy).
func TestOwnTypeNotFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "widget_var_lib_t", Class: "file",
		Perms: []string{"write"}, Path: "/var/lib/widget/x",
	}}
	if res := Refine(p, ds); len(res.Flags) != 0 {
		t.Errorf("own type must not be flagged: %+v", res.Flags)
	}
}
