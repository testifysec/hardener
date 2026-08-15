# splunkuf — SELinux confinement report

- License class: proprietary closed-source — freely distributable forwarder
- Source: https://download.splunk.com (universalforwarder aarch64 RPM)
- Domain: `splunkuf_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 13 | 8 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `splunkuf_t`: ✅
- Exercise passes under Enforcing: ✅
- Residual AVC denials: 0

## Static least-privilege checks

- no shadow_t read/write: ✅
- no etc_t write: ✅
- no sys_admin capability: ✅
- no sys_module capability: ✅
- no kernel module load: ✅
- not permissive: ✅
- no selinux mgmt: ✅

## Coverage cross-check (static import analysis)

- `cap-chown` (imports chown) — **NOT observed at runtime: exercise likely does not cover this**
- `cap-ipc-lock` (imports mlock) — **NOT observed at runtime: exercise likely does not cover this**
- `cap-setgid` (imports setgroups, setresgid) — **NOT observed at runtime: exercise likely does not cover this**
- `cap-setuid` (imports setresuid) — **NOT observed at runtime: exercise likely does not cover this**
- `dns-resolve` (imports getaddrinfo)
- `exec-other` (imports execve, execvp, popen, system)
- `file-unlink` (imports unlink)
- `fork` (imports fork)
- `outbound-connect` (imports connect) — **NOT observed at runtime: exercise likely does not cover this**
- `port-bind` (imports accept, bind, listen)

## Artifact

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/splunkuf-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(splunkuf, 1.0.0)

type splunkuf_t;
type splunkuf_exec_t;
init_daemon_domain(splunkuf_t, splunkuf_exec_t)

type splunkuf_content_t;
files_type(splunkuf_content_t)

########################################
# Base daemon rules
########################################
allow splunkuf_t self:process { fork signal signull sigkill getsched setsched };
allow splunkuf_t self:fifo_file rw_fifo_file_perms;
allow splunkuf_t self:unix_stream_socket create_stream_socket_perms;
allow splunkuf_t self:unix_dgram_socket create_socket_perms;
can_exec(splunkuf_t, splunkuf_exec_t)
kernel_read_system_state(splunkuf_t)
corecmd_exec_bin(splunkuf_t)
corecmd_exec_shell(splunkuf_t)
libs_exec_ldconfig(splunkuf_t)
miscfiles_read_localization(splunkuf_t)
miscfiles_read_generic_certs(splunkuf_t)
logging_send_syslog_msg(splunkuf_t)
files_read_etc_files(splunkuf_t)
files_read_usr_files(splunkuf_t)
fs_getattr_all_fs(splunkuf_t)
dev_read_urand(splunkuf_t)
dev_read_rand(splunkuf_t)
dev_read_sysfs(splunkuf_t)
auth_use_nsswitch(splunkuf_t)

########################################
# App file access
########################################
manage_dirs_pattern(splunkuf_t, splunkuf_content_t, splunkuf_content_t)
manage_files_pattern(splunkuf_t, splunkuf_content_t, splunkuf_content_t)
manage_lnk_files_pattern(splunkuf_t, splunkuf_content_t, splunkuf_content_t)
manage_sock_files_pattern(splunkuf_t, splunkuf_content_t, splunkuf_content_t)

########################################
# Observed refinements
########################################
gen_require(`
	type init_t;
	type root_t;
	type systemd_systemctl_exec_t;
	type unreserved_port_t;
')
allow splunkuf_t init_t:lnk_file read;
allow splunkuf_t root_t:dir watch;
allow splunkuf_t splunkuf_content_t:file { execute execute_no_trans map };
allow splunkuf_t splunkuf_exec_t:file setattr;
allow splunkuf_t splunkuf_t:process execmem;
allow splunkuf_t splunkuf_t:unix_dgram_socket sendto;
allow splunkuf_t systemd_systemctl_exec_t:file { execute execute_no_trans getattr map open read };
allow splunkuf_t unreserved_port_t:tcp_socket name_bind;
```

## File contexts (.fc)

```
/opt/splunkforwarder/bin/splunk	--	gen_context(system_u:object_r:splunkuf_exec_t,s0)
/opt/splunkforwarder/bin/splunkd	--	gen_context(system_u:object_r:splunkuf_exec_t,s0)
/opt/splunkforwarder(/.*)?	gen_context(system_u:object_r:splunkuf_content_t,s0)
```
