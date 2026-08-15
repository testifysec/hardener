# navidrome — SELinux confinement report

- License class: open-source (GPL-3.0)
- Source: https://github.com/navidrome/navidrome/releases (linux_arm64 tarball)
- Domain: `navidrome_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 5 | 4 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `navidrome_t`: ✅
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

## Artifact

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/navidrome-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(navidrome, 1.0.0)

type navidrome_t;
type navidrome_exec_t;
init_daemon_domain(navidrome_t, navidrome_exec_t)

type navidrome_var_lib_t;
files_type(navidrome_var_lib_t)
type navidrome_port_t;
corenet_port(navidrome_port_t)

########################################
# Base daemon rules
########################################
allow navidrome_t self:process { fork signal signull sigkill getsched setsched };
allow navidrome_t self:fifo_file rw_fifo_file_perms;
allow navidrome_t self:unix_stream_socket create_stream_socket_perms;
allow navidrome_t self:unix_dgram_socket create_socket_perms;
can_exec(navidrome_t, navidrome_exec_t)
kernel_read_system_state(navidrome_t)
corecmd_exec_bin(navidrome_t)
corecmd_exec_shell(navidrome_t)
libs_exec_ldconfig(navidrome_t)
miscfiles_read_localization(navidrome_t)
miscfiles_read_generic_certs(navidrome_t)
logging_send_syslog_msg(navidrome_t)
files_read_etc_files(navidrome_t)
files_read_usr_files(navidrome_t)
fs_getattr_all_fs(navidrome_t)
dev_read_urand(navidrome_t)
dev_read_rand(navidrome_t)
dev_read_sysfs(navidrome_t)
auth_use_nsswitch(navidrome_t)

########################################
# App file access
########################################
manage_dirs_pattern(navidrome_t, navidrome_var_lib_t, navidrome_var_lib_t)
manage_files_pattern(navidrome_t, navidrome_var_lib_t, navidrome_var_lib_t)
manage_lnk_files_pattern(navidrome_t, navidrome_var_lib_t, navidrome_var_lib_t)
manage_sock_files_pattern(navidrome_t, navidrome_var_lib_t, navidrome_var_lib_t)
files_var_lib_filetrans(navidrome_t, navidrome_var_lib_t, { dir file })

########################################
# Network
########################################
allow navidrome_t self:tcp_socket create_stream_socket_perms;
allow navidrome_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(navidrome_t)
corenet_udp_bind_generic_node(navidrome_t)
allow navidrome_t navidrome_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type http_port_t;
	type sysctl_net_t;
')
allow navidrome_t http_port_t:tcp_socket name_connect;
allow navidrome_t navidrome_var_lib_t:file map;
allow navidrome_t sysctl_net_t:dir search;
allow navidrome_t sysctl_net_t:file { open read };
```

## File contexts (.fc)

```
/opt/navidrome/bin/navidrome	--	gen_context(system_u:object_r:navidrome_exec_t,s0)
/var/lib/navidrome(/.*)?	gen_context(system_u:object_r:navidrome_var_lib_t,s0)
```
