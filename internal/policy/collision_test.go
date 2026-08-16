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

// Round 13: GenerateFC emits an _exec_t line for every executable, so an
// executable path the distro already claims collides exactly like a path claim
// — an undetected duplicate spec makes semodule reject the whole module. The
// collision must be detected AND excluded from the rendered fc.
func TestFindCollisionsDetectsExecutables(t *testing.T) {
	base := "/usr/sbin/myapp\t--\tsystem_u:object_r:bin_t:s0\n"
	p := &profile.Profile{
		Name:        "myapp",
		Executables: []string{"/usr/sbin/myapp"},
	}
	cols := FindCollisions(p, base)
	if len(cols) != 1 || cols[0].Path != "/usr/sbin/myapp" {
		t.Fatalf("executable collision must be detected, got %+v", cols)
	}
	if cols[0].BaseType != "bin_t" || cols[0].WouldBeType != "myapp_exec_t" {
		t.Errorf("collision fields: %+v", cols[0])
	}
	fc := GenerateFCExcluding(p, cols)
	if strings.Contains(fc, "/usr/sbin/myapp") {
		t.Errorf("colliding executable must be excluded from fc:\n%s", fc)
	}
	// An executable the distro does NOT claim is still emitted.
	p2 := &profile.Profile{Name: "myapp", Executables: []string{"/opt/myapp/bin/myapp"}}
	if cols := FindCollisions(p2, base); len(cols) != 0 {
		t.Errorf("unclaimed executable must not collide: %+v", cols)
	}
}

// Round 14: GenerateFC ESCAPES the executable path (spaces → \s), so the base
// claim to match is the escaped form. Comparing the raw path missed a collision
// like "Plex\sMedia\sServer", leaving a duplicate spec that makes semodule
// reject the module. The collision must be found (matching escaped) yet record
// the RAW path so exclusion still works.
func TestFindCollisionsMatchesEscapedExecutable(t *testing.T) {
	base := "/usr/lib/plexmediaserver/Plex\\sMedia\\sServer\t--\tsystem_u:object_r:bin_t:s0\n"
	p := &profile.Profile{
		Name:        "plex",
		Executables: []string{"/usr/lib/plexmediaserver/Plex Media Server"},
	}
	cols := FindCollisions(p, base)
	if len(cols) != 1 {
		t.Fatalf("escaped-executable collision must be detected, got %+v", cols)
	}
	if cols[0].Path != "/usr/lib/plexmediaserver/Plex Media Server" {
		t.Errorf("collision must record the RAW path for exclusion, got %q", cols[0].Path)
	}
	if fc := GenerateFCExcluding(p, cols); strings.Contains(fc, "Plex") {
		t.Errorf("colliding spaced executable must be excluded from fc:\n%s", fc)
	}
}

// Round 13: systemd unit files must take the shared base type so systemd can
// load them — and so the module never emits an fc entry referencing a type it
// never declares (app_unit_file_t was undeclared → uncompilable module).
func TestUnitPathUsesBaseSystemdType(t *testing.T) {
	if got := TypeForKind("myapp", KindUnit); got != "systemd_unit_file_t" {
		t.Errorf("unit kind must map to base systemd_unit_file_t, got %q", got)
	}
	p := &profile.Profile{Name: "myapp", Paths: []profile.PathAccess{
		{Path: "/usr/lib/systemd/system/myapp.service", Kind: "unit"},
	}}
	if IsOwnType(p, "systemd_unit_file_t") {
		t.Error("systemd_unit_file_t is a base type, not app-owned")
	}
	fc, te := GenerateFC(p), GenerateTE(p)
	if !strings.Contains(fc, "systemd_unit_file_t") {
		t.Errorf("unit path fc must use base systemd type:\n%s", fc)
	}
	// Neither fc nor te may reference an undeclared app unit type.
	if strings.Contains(fc, "myapp_unit_file_t") || strings.Contains(te, "myapp_unit_file_t") {
		t.Errorf("must not reference undeclared app unit type\nfc:\n%s\nte:\n%s", fc, te)
	}
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
