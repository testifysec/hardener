# nats-server — SELinux confinement report

- License class: open-source (Apache-2.0)
- Source: https://github.com/nats-io/nats-server/releases (arm64 RPM)
- Domain: `nats_server_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 3 | 2 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `nats_server_t`: ✅
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

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/nats_server-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(nats_server, 1.0.0)

type nats_server_t;
type nats_server_exec_t;
init_daemon_domain(nats_server_t, nats_server_exec_t)

type nats_server_conf_t;
files_config_file(nats_server_conf_t)
type nats_server_var_lib_t;
files_type(nats_server_var_lib_t)
type nats_server_log_t;
logging_log_file(nats_server_log_t)
type nats_server_port_t;
corenet_port(nats_server_port_t)

########################################
# Base daemon rules
########################################
allow nats_server_t self:process { fork signal signull sigkill getsched setsched };
allow nats_server_t self:fifo_file rw_fifo_file_perms;
allow nats_server_t self:unix_stream_socket create_stream_socket_perms;
allow nats_server_t self:unix_dgram_socket create_socket_perms;
can_exec(nats_server_t, nats_server_exec_t)
kernel_read_system_state(nats_server_t)
corecmd_exec_bin(nats_server_t)
corecmd_exec_shell(nats_server_t)
libs_exec_ldconfig(nats_server_t)
miscfiles_read_localization(nats_server_t)
miscfiles_read_generic_certs(nats_server_t)
logging_send_syslog_msg(nats_server_t)
files_read_etc_files(nats_server_t)
files_read_usr_files(nats_server_t)
fs_getattr_all_fs(nats_server_t)
dev_read_urand(nats_server_t)
dev_read_rand(nats_server_t)
dev_read_sysfs(nats_server_t)
auth_use_nsswitch(nats_server_t)

########################################
# App file access
########################################
allow nats_server_t nats_server_conf_t:dir list_dir_perms;
read_files_pattern(nats_server_t, nats_server_conf_t, nats_server_conf_t)
read_lnk_files_pattern(nats_server_t, nats_server_conf_t, nats_server_conf_t)
manage_dirs_pattern(nats_server_t, nats_server_var_lib_t, nats_server_var_lib_t)
manage_files_pattern(nats_server_t, nats_server_var_lib_t, nats_server_var_lib_t)
manage_lnk_files_pattern(nats_server_t, nats_server_var_lib_t, nats_server_var_lib_t)
manage_sock_files_pattern(nats_server_t, nats_server_var_lib_t, nats_server_var_lib_t)
files_var_lib_filetrans(nats_server_t, nats_server_var_lib_t, { dir file })
allow nats_server_t nats_server_log_t:dir { add_entry_dir_perms list_dir_perms };
create_files_pattern(nats_server_t, nats_server_log_t, nats_server_log_t)
append_files_pattern(nats_server_t, nats_server_log_t, nats_server_log_t)
setattr_files_pattern(nats_server_t, nats_server_log_t, nats_server_log_t)
logging_log_filetrans(nats_server_t, nats_server_log_t, { dir file })

########################################
# Network
########################################
allow nats_server_t self:tcp_socket create_stream_socket_perms;
allow nats_server_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(nats_server_t)
corenet_udp_bind_generic_node(nats_server_t)
allow nats_server_t nats_server_port_t:tcp_socket name_bind;
allow nats_server_t nats_server_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type sysctl_net_t;
')
allow nats_server_t sysctl_net_t:dir search;
allow nats_server_t sysctl_net_t:file { open read };
```

## File contexts (.fc)

```
/usr/bin/nats-server	--	gen_context(system_u:object_r:nats_server_exec_t,s0)
/etc/nats(/.*)?	gen_context(system_u:object_r:nats_server_conf_t,s0)
/var/lib/nats(/.*)?	gen_context(system_u:object_r:nats_server_var_lib_t,s0)
/var/log/nats(/.*)?	gen_context(system_u:object_r:nats_server_log_t,s0)
```
