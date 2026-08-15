package avc

import "testing"

// Kernel AVC records often carry only name= (basename). The full path lives
// in the sibling type=PATH record of the same audit event. Without
// correlation, a mislabeled file whose AVC lacks path= falls through to an
// allow rule — granting type-wide access where a relabel was the fix.
func TestCorrelatePathsFillsMissingPath(t *testing.T) {
	log := `type=AVC msg=audit(1786000000.100:501): avc:  denied  { write } for  pid=10 comm="widgetd" name="state.db" dev="vda2" ino=77 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=1
type=PATH msg=audit(1786000000.100:501): item=0 name="/var/lib/widget/state.db" inode=77 dev=fd:02 mode=0100644 obj=system_u:object_r:var_lib_t:s0
type=AVC msg=audit(1786000000.200:502): avc:  denied  { read } for  pid=10 comm="widgetd" path="/etc/pki/cert.pem" dev="vda2" ino=88 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:cert_t:s0 tclass=file permissive=1
`
	ds := ParseLogWithPaths(log)
	if len(ds) != 2 {
		t.Fatalf("want 2 denials, got %d", len(ds))
	}
	if ds[0].Path != "/var/lib/widget/state.db" {
		t.Errorf("path not correlated from PATH record: %q", ds[0].Path)
	}
	if ds[1].Path != "/etc/pki/cert.pem" {
		t.Errorf("existing path must be preserved: %q", ds[1].Path)
	}
}

// A PATH record from a DIFFERENT event must not leak onto a denial.
func TestCorrelatePathsRespectsEventID(t *testing.T) {
	log := `type=AVC msg=audit(1786000000.100:601): avc:  denied  { write } for  pid=10 comm="widgetd" name="a" dev="vda2" ino=1 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=1
type=PATH msg=audit(1786000000.100:999): item=0 name="/somewhere/else" inode=2 dev=fd:02
`
	ds := ParseLogWithPaths(log)
	if len(ds) != 1 || ds[0].Path != "" {
		t.Errorf("foreign event's PATH must not attach: %+v", ds)
	}
}
