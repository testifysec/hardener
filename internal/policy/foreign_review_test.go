package policy

import (
	"strings"
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
		SourceType: "widget_t", TargetType: "net_conf_t", Class: "file",
		Perms: []string{"read", "open"}, Path: "/etc/resolv.conf",
	}}
	if res := Refine(p, ds); len(res.Flags) != 0 {
		t.Errorf("net_conf_t is safe and must not be flagged: %+v", res.Flags)
	}
}

// Round 12, finding #4: EXECUTING a safe foreign DATA type is not routine read
// access and must go to review. allReadOnly counted execute as read-only, so a
// cert_t:file execute auto-applied foreign-content execution past the reviewer.
func TestSafeForeignTypeExecuteFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "net_conf_t", Class: "file",
		Perms: []string{"execute"}, Path: "/etc/resolv.conf",
	}}
	res := Refine(p, ds)
	if len(res.Flags) != 1 {
		t.Fatalf("execute of a foreign data type (cert_t) must be flagged for review, got %+v", res)
	}
	if len(res.AllowRules) != 0 {
		t.Errorf("flagged foreign execute must not auto-apply: %v", res.AllowRules)
	}
}

// Executing a foreign *_exec_t type (a binary the distro means to be run, e.g.
// hostname_exec_t) IS routine and stays auto-applied — the fix must scope the
// execute restriction to non-exec types, not block legitimate system-binary
// execution.
func TestSafeForeignExecTypeExecuteAllowed(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "hostname_exec_t", Class: "file",
		Perms: []string{"execute", "read", "open"}, Path: "/usr/bin/hostname",
	}}
	if res := Refine(p, ds); len(res.Flags) != 0 {
		t.Errorf("execute of hostname_exec_t is routine and must not be flagged: %+v", res.Flags)
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

// A safe foreign type is safe only for READ-ish access. A write/create/unlink
// to cert_t or sysctl_net_t must still be flagged (review finding).
func TestWriteToSafeForeignTypeFlagged(t *testing.T) {
	p := widgetProfile()
	for _, tc := range []struct {
		typ  string
		perm string
	}{
		{"cert_t", "write"},
		{"cert_t", "unlink"},
		{"sysctl_net_t", "write"},
		{"cert_t", "create"},
	} {
		ds := []avc.Denial{{
			SourceType: "widget_t", TargetType: tc.typ, Class: "file", Perms: []string{tc.perm},
		}}
		if res := Refine(p, ds); len(res.Flags) != 1 {
			t.Errorf("%s:file %s must be flagged despite %s being read-safe: %+v", tc.typ, tc.perm, tc.typ, res.Flags)
		}
	}
}

// A daemon writing its OWN content/exec files must go to review, not auto-
// apply: GenerateTE makes those read-only precisely to deny self-modification
// (a persistence primitive). Own-type WRITE denials previously slipped the
// gate because only foreign types reached the fallback flag.
func TestMutatingOwnContentExecFlagged(t *testing.T) {
	p := widgetProfile()
	for _, tc := range []struct{ typ, perm string }{
		{"widget_content_t", "write"},
		{"widget_content_t", "unlink"},
		{"widget_exec_t", "write"},
		{"widget_exec_t", "append"},
	} {
		ds := []avc.Denial{{
			SourceType: "widget_t", TargetType: tc.typ, Class: "file", Perms: []string{tc.perm},
		}}
		res := Refine(p, ds)
		if len(res.Flags) != 1 {
			t.Errorf("%s:file %s (self-modification) must be flagged: %+v", tc.typ, tc.perm, res.Flags)
		}
	}
}

// Reading/executing own content is fine (that's the point) — not flagged.
func TestReadingOwnContentNotFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "widget_content_t", Class: "file",
		Perms: []string{"read", "open", "execute"},
	}}
	if res := Refine(p, ds); len(res.Flags) != 0 {
		t.Errorf("reading/executing own content must not be flagged: %+v", res.Flags)
	}
}

// Round 17: a bind of a FOREIGN port type (ssh_port_t, unreserved_port_t) is a
// broad grant that must go to review — the blanket _port_t skip let those be
// auto-accepted as the app's declared port.
func TestForeignPortTypeFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "ssh_port_t", Class: "tcp_socket",
		Perms: []string{"name_bind"},
	}}
	res := Refine(p, ds)
	if len(res.Flags) != 1 {
		t.Fatalf("foreign port bind must be flagged, got %+v", res)
	}
	if len(res.AllowRules) != 0 {
		t.Errorf("flagged foreign port must not auto-apply: %v", res.AllowRules)
	}
}

// The app's OWN port type is declared by the module, so binding it is expected
// and must NOT be flagged.
func TestOwnPortTypeNotFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "widget_port_t", Class: "tcp_socket",
		Perms: []string{"name_bind"},
	}}
	if res := Refine(p, ds); len(res.Flags) != 0 {
		t.Errorf("own port type must not be flagged: %+v", res.Flags)
	}
}

// Round 39: cert_t labels TLS PRIVATE KEYS as well as public certs, so an
// automatic read grant would let a confined daemon read other services' keys.
// It must go to review.
func TestCertTReadIsFlagged(t *testing.T) {
	p := widgetProfile()
	ds := []avc.Denial{{
		SourceType: "widget_t", TargetType: "cert_t", Class: "file",
		Perms: []string{"read", "open"}, Path: "/etc/pki/tls/private/key.pem",
	}}
	res := Refine(p, ds)
	if len(res.Flags) != 1 {
		t.Fatalf("cert_t read must be flagged for review, got %+v", res.Flags)
	}
}

// Round 39: executing from a WRITABLE owned type (var_lib/log/runtime/tmp/cache)
// is a W^X violation and must go to review, not auto-apply.
func TestExecuteFromWritableOwnedTypeFlagged(t *testing.T) {
	p := widgetProfile()
	for _, wt := range []string{"widget_var_lib_t", "widget_log_t", "widget_tmp_t", "widget_cache_t", "widget_runtime_t"} {
		ds := []avc.Denial{{
			SourceType: "widget_t", TargetType: wt, Class: "file",
			Perms: []string{"execute", "open", "read"},
		}}
		res := Refine(p, ds)
		flagged := false
		for _, f := range res.Flags {
			if strings.Contains(f.Reason, "W^X") {
				flagged = true
			}
		}
		if !flagged {
			t.Errorf("execute from writable %s must be flagged (W^X), got %+v", wt, res.Flags)
		}
	}
}
