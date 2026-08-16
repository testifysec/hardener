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
		Ino:        "5678",
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

// Round 15: auditd with name_format set prefixes every record with
// `node=<hostname> `. The parser must still recognize these — an anchored
// `^type=` pre-filter in the pipeline used to drop them, making real AVCs on
// such hosts vanish (review finding). ParseLine/ParseLogWithPaths match by
// substring, so the prefix must not defeat them.
func TestParseNodePrefixedRecords(t *testing.T) {
	line := `node=web01.corp type=AVC msg=audit(1723640000.1:99): avc:  denied  { read } for  pid=7 comm="widgetd" scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`
	d, err := ParseLine(line)
	if err != nil {
		t.Fatalf("node=-prefixed AVC must parse: %v", err)
	}
	if d.SourceType != "widget_t" || d.TargetType != "shadow_t" {
		t.Errorf("wrong denial parsed: %+v", d)
	}
	ds := ParseLogWithPaths(line + "\n")
	if len(ds) != 1 || ds[0].TargetType != "shadow_t" {
		t.Errorf("ParseLogWithPaths must return the node=-prefixed denial, got %+v", ds)
	}
}

// Round 21: distinct paths that share an SELinux type must NOT be merged into
// one denial — merging dropped a path and let a per-path classification (a
// relabel, or which file is the mislabeled entrypoint) apply to the wrong file.
func TestMergeKeepsDistinctPaths(t *testing.T) {
	out := Merge([]Denial{
		{SourceType: "init_t", TargetType: "app_content_t", Class: "file", Perms: []string{"execute"}, Path: "/opt/a", Ino: "1"},
		{SourceType: "init_t", TargetType: "app_content_t", Class: "file", Perms: []string{"execute"}, Path: "/opt/b", Ino: "2"},
	})
	if len(out) != 2 {
		t.Fatalf("distinct paths with the same type must not be merged, got %d: %+v", len(out), out)
	}
	// The same path still unions perms into one denial.
	same := Merge([]Denial{
		{SourceType: "s_t", TargetType: "t_t", Class: "file", Perms: []string{"read"}, Path: "/x", Ino: "1"},
		{SourceType: "s_t", TargetType: "t_t", Class: "file", Perms: []string{"write"}, Path: "/x", Ino: "1"},
	})
	if len(same) != 1 || len(same[0].Perms) != 2 {
		t.Errorf("same path+type must union perms into one denial: %+v", same)
	}
}

// Round 23: two name_bind denials on DIFFERENT ports share the same *_port_t
// type/class and must not collapse to the first port (Src is part of the key).
func TestMergeKeepsDistinctPorts(t *testing.T) {
	out := Merge([]Denial{
		{SourceType: "app_t", TargetType: "http_port_t", Class: "tcp_socket", Perms: []string{"name_bind"}, Src: 8080},
		{SourceType: "app_t", TargetType: "http_port_t", Class: "tcp_socket", Perms: []string{"name_bind"}, Src: 8443},
	})
	if len(out) != 2 {
		t.Fatalf("distinct ports must not merge, got %d: %+v", len(out), out)
	}
}

// A PATH record can carry a RELATIVE name (the syscall used a relative path),
// with the working directory in a sibling type=CWD record. Correlating them
// yields the absolute path; taking name= verbatim would leave a bare basename
// that matches no file-context pattern, so a mislabel is misread as a missing
// permission and over-granted type-wide. (review finding — round 49)
func TestParseLogResolvesRelativePathAgainstCWD(t *testing.T) {
	log := `type=AVC msg=audit(1723640005.000:500): avc:  denied  { write } for  pid=1234 comm="widgetd" ino=42 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=1
type=CWD msg=audit(1723640005.000:500): cwd="/var/lib/widget"
type=PATH msg=audit(1723640005.000:500): item=0 name="sub/state.db" inode=42 dev="vda2" mode=0100644`
	ds := ParseLogWithPaths(log + "\n")
	if len(ds) != 1 {
		t.Fatalf("want 1 denial, got %d: %+v", len(ds), ds)
	}
	if ds[0].Path != "/var/lib/widget/sub/state.db" {
		t.Errorf("relative name must resolve against CWD, got %q", ds[0].Path)
	}
}

// An absolute PATH name is unaffected by any CWD record.
func TestParseLogKeepsAbsolutePathDespiteCWD(t *testing.T) {
	log := `type=AVC msg=audit(1723640006.000:501): avc:  denied  { read } for  pid=1234 comm="widgetd" ino=7 scontext=system_u:system_r:widget_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=1
type=CWD msg=audit(1723640006.000:501): cwd="/tmp"
type=PATH msg=audit(1723640006.000:501): item=0 name="/etc/widget/widget.conf" inode=7 dev="vda2"`
	ds := ParseLogWithPaths(log + "\n")
	if len(ds) != 1 {
		t.Fatalf("want 1 denial, got %d: %+v", len(ds), ds)
	}
	if ds[0].Path != "/etc/widget/widget.conf" {
		t.Errorf("absolute name must be preserved, got %q", ds[0].Path)
	}
}
