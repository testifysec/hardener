package policy

import "testing"

func TestClassifyPath(t *testing.T) {
	cases := []struct {
		path string
		exec bool
		want Kind
	}{
		{"/etc/widget/widget.conf", false, KindConf},
		{"/etc/widget", false, KindConf},
		{"/var/lib/widget/state.db", false, KindVarLib},
		{"/var/log/widget/widget.log", false, KindLog},
		{"/run/widget/widget.sock", false, KindRuntime},
		{"/var/run/widget/widget.pid", false, KindRuntime},
		{"/opt/widget/bin/widgetd", true, KindExec},
		{"/usr/bin/widgetd", true, KindExec},
		{"/opt/widget/share/schema.sql", false, KindContent},
		{"/usr/lib/systemd/system/widget.service", false, KindUnit},
		{"/tmp/widget.tmp", false, KindTmp},
		{"/var/cache/widget/blob", false, KindCache},
	}
	for _, c := range cases {
		got := ClassifyPath(c.path, c.exec)
		if got != c.want {
			t.Errorf("ClassifyPath(%q, exec=%v) = %v, want %v", c.path, c.exec, got, c.want)
		}
	}
}

func TestTypeForKind(t *testing.T) {
	cases := []struct {
		kind Kind
		want string
	}{
		{KindExec, "widget_exec_t"},
		{KindConf, "widget_conf_t"},
		{KindVarLib, "widget_var_lib_t"},
		{KindLog, "widget_log_t"},
		{KindRuntime, "widget_runtime_t"},
		{KindContent, "widget_content_t"},
		{KindTmp, "widget_tmp_t"},
		{KindCache, "widget_cache_t"},
	}
	for _, c := range cases {
		if got := TypeForKind("widget", c.kind); got != c.want {
			t.Errorf("TypeForKind(widget, %v) = %q, want %q", c.kind, got, c.want)
		}
	}
}

// Module names must be valid SELinux identifiers even when the app name isn't.
func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"widget":           "widget",
		"1password-cli":    "app_1password_cli",
		"plexmediaserver":  "plexmediaserver",
		"speedtest-cli":    "speedtest_cli",
		"nats-server":      "nats_server",
		"Weird App (v2).x": "weird_app_v2_x",
	}
	for in, want := range cases {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Round 70: a top-level path merely PREFIXED with "etc" (/etcd, /etcetera) is not
// under /etc and must not be classified KindConf — doing so synthesizes the wrong
// SELinux type for an unrelated tree. The legitimate /etc space (/etc itself and
// anything beneath it) must still classify as KindConf. (review finding)
func TestClassifyEtcPrefixIsNotEtc(t *testing.T) {
	conf := []string{"/etc", "/etc/widget.conf", "/etc/widget/sub/x.yaml"}
	for _, p := range conf {
		if k := ClassifyPath(p, false); k != KindConf {
			t.Errorf("ClassifyPath(%q) = %v, want KindConf", p, k)
		}
	}
	notConf := []string{"/etcd", "/etcetera", "/etcd/data"}
	for _, p := range notConf {
		if k := ClassifyPath(p, false); k == KindConf {
			t.Errorf("ClassifyPath(%q) = KindConf, but it is not under /etc", p)
		}
	}
}
