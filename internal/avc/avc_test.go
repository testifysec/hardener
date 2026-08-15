package avc

import (
	"reflect"
	"testing"
)

func TestParseFileDenial(t *testing.T) {
	line := `type=AVC msg=audit(1723640000.123:456): avc:  denied  { read open } for  pid=1234 comm="widgetd" name="widget.conf" dev="vda2" ino=5678 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=1`
	d, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	want := Denial{
		Perms:      []string{"open", "read"},
		Comm:       "widgetd",
		Name:       "widget.conf",
		SourceType: "widget_t",
		TargetType: "etc_t",
		Class:      "file",
		Permissive: true,
	}
	if !reflect.DeepEqual(*d, want) {
		t.Errorf("got %+v want %+v", *d, want)
	}
}

func TestParsePathDenial(t *testing.T) {
	line := `type=AVC msg=audit(1723640001.000:457): avc:  denied  { write } for  pid=1234 comm="widgetd" path="/var/lib/widget/state.db" dev="vda2" ino=99 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=0`
	d, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if d.Path != "/var/lib/widget/state.db" {
		t.Errorf("path: got %q", d.Path)
	}
	if d.Permissive {
		t.Error("permissive should be false")
	}
	if d.TargetType != "var_lib_t" {
		t.Errorf("target type: got %q", d.TargetType)
	}
}

func TestParsePortDenial(t *testing.T) {
	line := `type=AVC msg=audit(1723640002.000:458): avc:  denied  { name_bind } for  pid=1234 comm="widgetd" src=8443 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=1`
	d, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if d.Src != 8443 {
		t.Errorf("src port: got %d", d.Src)
	}
	if d.Class != "tcp_socket" {
		t.Errorf("class: got %q", d.Class)
	}
}

func TestParseCapabilityDenial(t *testing.T) {
	line := `type=AVC msg=audit(1723640003.000:459): avc:  denied  { net_bind_service } for  pid=1234 comm="widgetd" capability=10 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:system_r:widget_t:s0 tclass=capability permissive=1`
	d, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if d.Class != "capability" {
		t.Errorf("class: got %q", d.Class)
	}
	if !reflect.DeepEqual(d.Perms, []string{"net_bind_service"}) {
		t.Errorf("perms: got %v", d.Perms)
	}
}

func TestParseIgnoresNonAVC(t *testing.T) {
	if _, err := ParseLine(`type=SYSCALL msg=audit(1723640000.123:456): arch=c00000b7 syscall=56`); err == nil {
		t.Error("expected error for non-AVC line")
	}
}

func TestParseLog(t *testing.T) {
	log := `----
time->Wed Aug 14 10:00:00 2026
type=PROCTITLE msg=audit(1723640000.123:456): proctitle="/opt/widget/bin/widgetd"
type=SYSCALL msg=audit(1723640000.123:456): arch=c00000b7 syscall=56 success=yes
type=AVC msg=audit(1723640000.123:456): avc:  denied  { read } for  pid=1 comm="widgetd" name="a" dev="vda2" ino=1 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=1
----
type=AVC msg=audit(1723640001.123:457): avc:  denied  { write } for  pid=1 comm="widgetd" path="/x" dev="vda2" ino=2 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=1
<no matches>
`
	ds := ParseLog(log)
	if len(ds) != 2 {
		t.Fatalf("got %d denials, want 2", len(ds))
	}
}

// Denials for the same source/target/class must merge with permission union.
func TestMerge(t *testing.T) {
	ds := []Denial{
		{SourceType: "w_t", TargetType: "etc_t", Class: "file", Perms: []string{"read"}},
		{SourceType: "w_t", TargetType: "etc_t", Class: "file", Perms: []string{"open", "read"}},
		{SourceType: "w_t", TargetType: "var_t", Class: "dir", Perms: []string{"search"}},
	}
	m := Merge(ds)
	if len(m) != 2 {
		t.Fatalf("got %d merged, want 2", len(m))
	}
	for _, d := range m {
		if d.TargetType == "etc_t" && !reflect.DeepEqual(d.Perms, []string{"open", "read"}) {
			t.Errorf("merged perms: got %v", d.Perms)
		}
	}
}
