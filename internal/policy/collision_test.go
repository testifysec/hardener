package policy

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/avc"
	"github.com/testifysec/hardener/internal/profile"
)

func denialsOn(targetType string) []avc.Denial {
	return []avc.Denial{{
		SourceType: "widget_t", TargetType: targetType, Class: "file",
		Perms: []string{"write"}, Path: "/somewhere/else/file",
	}}
}

// The distro base policy already claims some paths. Re-declaring the identical
// path expression makes semodule reject the module outright
// ("Problems processing filecon rules"), so collisions must be found first.
func TestFindCollisions(t *testing.T) {
	base := `/var/webmin(/.*)?	system_u:object_r:var_log_t:s0
/usr/libexec/webmin/vsftpd/webalizer/xfer_log	--	system_u:object_r:xferlog_t:s0
/etc/other(/.*)?	system_u:object_r:etc_t:s0
`
	p := &profile.Profile{
		Name: "webmin",
		Paths: []profile.PathAccess{
			{Path: "/etc/webmin(/.*)?", Kind: "conf"},
			{Path: "/var/webmin(/.*)?", Kind: "var_lib"},
		},
	}
	cols := FindCollisions(p, base)
	if len(cols) != 1 {
		t.Fatalf("want 1 collision, got %+v", cols)
	}
	if cols[0].Path != "/var/webmin(/.*)?" || cols[0].BaseType != "var_log_t" {
		t.Errorf("collision: %+v", cols[0])
	}
	if cols[0].WouldBeType != "webmin_var_lib_t" {
		t.Errorf("would-be type: %q", cols[0].WouldBeType)
	}
}

// Re-running against a system where a previous version of OUR module is still
// installed is not a conflict: the claimed type is identical, so re-declaring
// it is idempotent. Treating it as a collision would silently drop our own
// labels and leave the app unconfined on the second run.
func TestFindCollisionsIgnoresOurOwnPriorInstall(t *testing.T) {
	base := `/etc/nats(/.*)?	system_u:object_r:nats_server_conf_t:s0
/var/lib/nats(/.*)?	system_u:object_r:nats_server_var_lib_t:s0
`
	p := &profile.Profile{
		Name: "nats-server",
		Paths: []profile.PathAccess{
			{Path: "/etc/nats(/.*)?", Kind: "conf"},
			{Path: "/var/lib/nats(/.*)?", Kind: "var_lib"},
		},
	}
	if cols := FindCollisions(p, base); len(cols) != 0 {
		t.Errorf("our own prior labels must not count as collisions, got %+v", cols)
	}
}

// Colliding entries must be dropped from the generated .fc so the module
// compiles; everything else is preserved.
func TestGenerateFCSkipsCollisions(t *testing.T) {
	p := &profile.Profile{
		Name: "webmin",
		Paths: []profile.PathAccess{
			{Path: "/etc/webmin(/.*)?", Kind: "conf"},
			{Path: "/var/webmin(/.*)?", Kind: "var_lib"},
		},
	}
	cols := []Collision{{Path: "/var/webmin(/.*)?", BaseType: "var_log_t", WouldBeType: "webmin_var_lib_t"}}
	fc := GenerateFCExcluding(p, cols)
	if strings.Contains(fc, "/var/webmin") {
		t.Errorf("colliding path must be dropped:\n%s", fc)
	}
	if !strings.Contains(fc, "/etc/webmin(/.*)?") {
		t.Errorf("non-colliding path must survive:\n%s", fc)
	}
}

// Granting a domain access to a broad shared type (var_log_t, var_lib_t, tmp_t)
// is the exact over-permission audit2allow produces; it needs human review.
func TestGenericTargetTypesAreFlagged(t *testing.T) {
	p := widgetProfile()
	for _, generic := range []string{"var_log_t", "var_lib_t", "tmp_t", "default_t"} {
		res := Refine(p, denialsOn(generic))
		if len(res.Flags) != 1 {
			t.Errorf("target %s: expected a review flag, got %+v", generic, res.Flags)
		}
	}
}
