# caddy — SELinux confinement report

- License class: open-source (Apache-2.0)
- Source: https://github.com/caddyserver/caddy/releases (linux_arm64 tarball)
- Domain: `caddy_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 3 | 2 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `caddy_t`: ✅
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

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/caddy-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(caddy, 1.0.0)

type caddy_t;
type caddy_exec_t;
init_daemon_domain(caddy_t, caddy_exec_t)

type caddy_conf_t;
files_config_file(caddy_conf_t)
type caddy_var_lib_t;
files_type(caddy_var_lib_t)
type caddy_log_t;
logging_log_file(caddy_log_t)
type caddy_port_t;
corenet_port(caddy_port_t)

########################################
# Base daemon rules
########################################
allow caddy_t self:process { fork signal signull sigkill getsched setsched };
allow caddy_t self:fifo_file rw_fifo_file_perms;
allow caddy_t self:unix_stream_socket create_stream_socket_perms;
allow caddy_t self:unix_dgram_socket create_socket_perms;
can_exec(caddy_t, caddy_exec_t)
kernel_read_system_state(caddy_t)
corecmd_exec_bin(caddy_t)
corecmd_exec_shell(caddy_t)
libs_exec_ldconfig(caddy_t)
miscfiles_read_localization(caddy_t)
miscfiles_read_generic_certs(caddy_t)
logging_send_syslog_msg(caddy_t)
files_read_etc_files(caddy_t)
files_read_usr_files(caddy_t)
fs_getattr_all_fs(caddy_t)
dev_read_urand(caddy_t)
dev_read_rand(caddy_t)
dev_read_sysfs(caddy_t)
auth_use_nsswitch(caddy_t)

########################################
# App file access
########################################
allow caddy_t caddy_conf_t:dir list_dir_perms;
read_files_pattern(caddy_t, caddy_conf_t, caddy_conf_t)
read_lnk_files_pattern(caddy_t, caddy_conf_t, caddy_conf_t)
manage_dirs_pattern(caddy_t, caddy_var_lib_t, caddy_var_lib_t)
manage_files_pattern(caddy_t, caddy_var_lib_t, caddy_var_lib_t)
manage_lnk_files_pattern(caddy_t, caddy_var_lib_t, caddy_var_lib_t)
manage_sock_files_pattern(caddy_t, caddy_var_lib_t, caddy_var_lib_t)
files_var_lib_filetrans(caddy_t, caddy_var_lib_t, { dir file })
allow caddy_t caddy_log_t:dir { add_entry_dir_perms list_dir_perms };
create_files_pattern(caddy_t, caddy_log_t, caddy_log_t)
append_files_pattern(caddy_t, caddy_log_t, caddy_log_t)
setattr_files_pattern(caddy_t, caddy_log_t, caddy_log_t)
logging_log_filetrans(caddy_t, caddy_log_t, { dir file })

########################################
# Network
########################################
allow caddy_t self:tcp_socket create_stream_socket_perms;
allow caddy_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(caddy_t)
corenet_udp_bind_generic_node(caddy_t)
allow caddy_t caddy_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type sysctl_net_t;
')
allow caddy_t sysctl_net_t:dir search;
allow caddy_t sysctl_net_t:file { open read };
```

## File contexts (.fc)

```
/opt/caddy/bin/caddy	--	gen_context(system_u:object_r:caddy_exec_t,s0)
/etc/caddy(/.*)?	gen_context(system_u:object_r:caddy_conf_t,s0)
/var/lib/caddy(/.*)?	gen_context(system_u:object_r:caddy_var_lib_t,s0)
/var/log/caddy(/.*)?	gen_context(system_u:object_r:caddy_log_t,s0)
```
