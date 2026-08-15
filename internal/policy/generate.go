package policy

import (
	"fmt"
	"strings"

	"github.com/testifysec/hardener/internal/profile"
)

// BaseInterfaces are the refpolicy interfaces every generated daemon domain
// receives unconditionally. They speed convergence but they are real
// privilege — shell execution, /etc read, cert/NSS access — that produces no
// AVC when the app uses it. Conformance therefore treats this set as observed
// behavior (see conformance.BaseGrantedAccess) so a second-party supplier
// cannot use, say, corecmd_exec_shell without declaring it. This is the single
// source of truth: the generator and the conformance check read the same list.
//
// Narrowing this set toward true least-privilege (observation-gating each
// interface) is tracked as follow-up; today it is generous-but-declared.
var BaseInterfaces = []string{
	"kernel_read_system_state",
	"corecmd_exec_bin",
	"corecmd_exec_shell",
	"libs_exec_ldconfig",
	"miscfiles_read_localization",
	"miscfiles_read_generic_certs",
	"logging_send_syslog_msg",
	"files_read_etc_files",
	"files_read_usr_files",
	"fs_getattr_all_fs",
	"dev_read_urand",
	"dev_read_rand",
	"dev_read_sysfs",
	"auth_use_nsswitch",
}

// GenerateTE renders the type-enforcement module for a profile.
func GenerateTE(p *profile.Profile) string {
	app := SafeName(p.Name)
	dom := DomainType(p.Name)
	var b strings.Builder

	fmt.Fprintf(&b, "policy_module(%s, 1.0.0)\n\n", app)

	fmt.Fprintf(&b, "type %s;\n", dom)
	fmt.Fprintf(&b, "type %s_exec_t;\n", app)
	fmt.Fprintf(&b, "init_daemon_domain(%s, %s_exec_t)\n\n", dom, app)

	kinds := map[Kind]bool{}
	for _, pa := range p.Paths {
		kinds[KindFromString(pa.Kind)] = true
	}

	if kinds[KindConf] {
		fmt.Fprintf(&b, "type %s_conf_t;\nfiles_config_file(%s_conf_t)\n", app, app)
	}
	if kinds[KindVarLib] {
		fmt.Fprintf(&b, "type %s_var_lib_t;\nfiles_type(%s_var_lib_t)\n", app, app)
	}
	if kinds[KindLog] {
		fmt.Fprintf(&b, "type %s_log_t;\nlogging_log_file(%s_log_t)\n", app, app)
	}
	if kinds[KindRuntime] {
		fmt.Fprintf(&b, "type %s_runtime_t;\nfiles_pid_file(%s_runtime_t)\n", app, app)
	}
	if kinds[KindTmp] {
		fmt.Fprintf(&b, "type %s_tmp_t;\nfiles_tmp_file(%s_tmp_t)\n", app, app)
	}
	if kinds[KindCache] {
		fmt.Fprintf(&b, "type %s_cache_t;\nfiles_type(%s_cache_t)\n", app, app)
	}
	if kinds[KindContent] {
		fmt.Fprintf(&b, "type %s_content_t;\nfiles_type(%s_content_t)\n", app, app)
	}
	if len(p.Ports) > 0 {
		fmt.Fprintf(&b, "type %s;\ncorenet_port(%s)\n", PortType(p.Name), PortType(p.Name))
	}
	b.WriteString("\n########################################\n# Base daemon rules\n########################################\n")

	// Self rules every real daemon needs.
	fmt.Fprintf(&b, "allow %s self:process { fork signal signull sigkill getsched setsched };\n", dom)
	fmt.Fprintf(&b, "allow %s self:fifo_file rw_fifo_file_perms;\n", dom)
	fmt.Fprintf(&b, "allow %s self:unix_stream_socket create_stream_socket_perms;\n", dom)
	fmt.Fprintf(&b, "allow %s self:unix_dgram_socket create_socket_perms;\n", dom)

	// The domain may execute its own binaries and shared libs.
	fmt.Fprintf(&b, "can_exec(%s, %s_exec_t)\n", dom, app)

	// Standard environment access.
	for _, iface := range BaseInterfaces {
		fmt.Fprintf(&b, iface+"(%s)\n", dom)
	}

	b.WriteString("\n########################################\n# App file access\n########################################\n")
	if kinds[KindConf] {
		fmt.Fprintf(&b, "allow %s %s_conf_t:dir list_dir_perms;\n", dom, app)
		fmt.Fprintf(&b, "read_files_pattern(%s, %s_conf_t, %s_conf_t)\n", dom, app, app)
		fmt.Fprintf(&b, "read_lnk_files_pattern(%s, %s_conf_t, %s_conf_t)\n", dom, app, app)
	}
	for _, k := range []struct {
		on   bool
		t    string
		base string
	}{
		{kinds[KindVarLib], app + "_var_lib_t", "files_var_lib_filetrans"},
		{kinds[KindCache], app + "_cache_t", ""},
	} {
		if !k.on {
			continue
		}
		fmt.Fprintf(&b, "manage_dirs_pattern(%s, %s, %s)\n", dom, k.t, k.t)
		fmt.Fprintf(&b, "manage_files_pattern(%s, %s, %s)\n", dom, k.t, k.t)
		fmt.Fprintf(&b, "manage_lnk_files_pattern(%s, %s, %s)\n", dom, k.t, k.t)
		fmt.Fprintf(&b, "manage_sock_files_pattern(%s, %s, %s)\n", dom, k.t, k.t)
	}
	if kinds[KindContent] {
		// Content is the application's own program tree (e.g. /opt/app): it is
		// READ-ONLY by default. A daemon that can rewrite its own binaries is a
		// persistence primitive (review finding). Read + traverse + execute
		// only; any genuine write need must be a reviewed refinement, or the
		// writable subtree must be declared as var_lib in the manifest.
		ct := app + "_content_t"
		fmt.Fprintf(&b, "allow %s %s:dir list_dir_perms;\n", dom, ct)
		fmt.Fprintf(&b, "read_files_pattern(%s, %s, %s)\n", dom, ct, ct)
		fmt.Fprintf(&b, "read_lnk_files_pattern(%s, %s, %s)\n", dom, ct, ct)
		fmt.Fprintf(&b, "can_exec(%s, %s)\n", dom, ct)
	}
	if kinds[KindVarLib] {
		fmt.Fprintf(&b, "files_var_lib_filetrans(%s, %s_var_lib_t, { dir file })\n", dom, app)
	}
	if kinds[KindLog] {
		fmt.Fprintf(&b, "allow %s %s_log_t:dir { add_entry_dir_perms list_dir_perms };\n", dom, app)
		fmt.Fprintf(&b, "create_files_pattern(%s, %s_log_t, %s_log_t)\n", dom, app, app)
		fmt.Fprintf(&b, "append_files_pattern(%s, %s_log_t, %s_log_t)\n", dom, app, app)
		fmt.Fprintf(&b, "setattr_files_pattern(%s, %s_log_t, %s_log_t)\n", dom, app, app)
		fmt.Fprintf(&b, "logging_log_filetrans(%s, %s_log_t, { dir file })\n", dom, app)
	}
	if kinds[KindRuntime] {
		fmt.Fprintf(&b, "manage_dirs_pattern(%s, %s_runtime_t, %s_runtime_t)\n", dom, app, app)
		fmt.Fprintf(&b, "manage_files_pattern(%s, %s_runtime_t, %s_runtime_t)\n", dom, app, app)
		fmt.Fprintf(&b, "manage_sock_files_pattern(%s, %s_runtime_t, %s_runtime_t)\n", dom, app, app)
		fmt.Fprintf(&b, "files_pid_filetrans(%s, %s_runtime_t, { dir file sock_file })\n", dom, app)
	}
	if kinds[KindTmp] {
		fmt.Fprintf(&b, "manage_dirs_pattern(%s, %s_tmp_t, %s_tmp_t)\n", dom, app, app)
		fmt.Fprintf(&b, "manage_files_pattern(%s, %s_tmp_t, %s_tmp_t)\n", dom, app, app)
		fmt.Fprintf(&b, "files_tmp_filetrans(%s, %s_tmp_t, { dir file })\n", dom, app)
	}

	if len(p.Ports) > 0 {
		b.WriteString("\n########################################\n# Network\n########################################\n")
		fmt.Fprintf(&b, "allow %s self:tcp_socket create_stream_socket_perms;\n", dom)
		fmt.Fprintf(&b, "allow %s self:udp_socket create_socket_perms;\n", dom)
		fmt.Fprintf(&b, "corenet_tcp_bind_generic_node(%s)\n", dom)
		fmt.Fprintf(&b, "corenet_udp_bind_generic_node(%s)\n", dom)
		// All ports of one protocol share the app's single port type.
		protos := map[string]bool{}
		for _, port := range p.Ports {
			protos[port.Proto] = true
		}
		for _, proto := range []string{"tcp", "udp"} {
			if protos[proto] {
				fmt.Fprintf(&b, "allow %s %s:%s_socket name_bind;\n", dom, PortType(p.Name), proto)
			}
		}
	}

	if len(p.Capabilities) > 0 {
		fmt.Fprintf(&b, "\nallow %s self:capability { %s };\n", dom, strings.Join(p.Capabilities, " "))
	}

	if len(p.Interfaces) > 0 {
		b.WriteString("\n########################################\n# Refined interfaces\n########################################\n")
		for _, iface := range p.Interfaces {
			fmt.Fprintf(&b, "%s(%s)\n", iface, dom)
		}
	}

	return b.String()
}

// GenerateFC renders the file-contexts module for a profile.
func GenerateFC(p *profile.Profile) string {
	var b strings.Builder
	for _, exe := range p.Executables {
		fmt.Fprintf(&b, "%s\t--\tgen_context(system_u:object_r:%s,s0)\n",
			escapeFCPath(exe), TypeForKind(p.Name, KindExec))
	}
	for _, pa := range p.Paths {
		fmt.Fprintf(&b, "%s\tgen_context(system_u:object_r:%s,s0)\n",
			pa.Path, TypeForKind(p.Name, KindFromString(pa.Kind)))
	}
	return b.String()
}

// escapeFCPath escapes regex metacharacters in a literal path for file_contexts.
func escapeFCPath(path string) string {
	var b strings.Builder
	for _, r := range path {
		switch r {
		case ' ':
			// fc lines are whitespace-delimited before regex parsing, so a
			// literal space (even inside [ ]) splits the fields. \s is the
			// only representation that survives the parser.
			b.WriteString(`\s`)
		case '.', '+', '*', '?', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			b.WriteRune('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
