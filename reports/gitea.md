# gitea — SELinux confinement report

- License class: open-source (MIT)
- Source: https://dl.gitea.com/gitea/ (linux-arm64 binary)
- Domain: `gitea_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 7 | 5 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `gitea_t`: ✅
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

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/gitea-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(gitea, 1.0.0)

type gitea_t;
type gitea_exec_t;
init_daemon_domain(gitea_t, gitea_exec_t)

type gitea_conf_t;
files_config_file(gitea_conf_t)
type gitea_var_lib_t;
files_type(gitea_var_lib_t)
type gitea_log_t;
logging_log_file(gitea_log_t)
type gitea_port_t;
corenet_port(gitea_port_t)

########################################
# Base daemon rules
########################################
allow gitea_t self:process { fork signal signull sigkill getsched setsched };
allow gitea_t self:fifo_file rw_fifo_file_perms;
allow gitea_t self:unix_stream_socket create_stream_socket_perms;
allow gitea_t self:unix_dgram_socket create_socket_perms;
can_exec(gitea_t, gitea_exec_t)
kernel_read_system_state(gitea_t)
corecmd_exec_bin(gitea_t)
corecmd_exec_shell(gitea_t)
libs_exec_ldconfig(gitea_t)
miscfiles_read_localization(gitea_t)
miscfiles_read_generic_certs(gitea_t)
logging_send_syslog_msg(gitea_t)
files_read_etc_files(gitea_t)
files_read_usr_files(gitea_t)
fs_getattr_all_fs(gitea_t)
dev_read_urand(gitea_t)
dev_read_rand(gitea_t)
dev_read_sysfs(gitea_t)
auth_use_nsswitch(gitea_t)

########################################
# App file access
########################################
allow gitea_t gitea_conf_t:dir list_dir_perms;
read_files_pattern(gitea_t, gitea_conf_t, gitea_conf_t)
read_lnk_files_pattern(gitea_t, gitea_conf_t, gitea_conf_t)
manage_dirs_pattern(gitea_t, gitea_var_lib_t, gitea_var_lib_t)
manage_files_pattern(gitea_t, gitea_var_lib_t, gitea_var_lib_t)
manage_lnk_files_pattern(gitea_t, gitea_var_lib_t, gitea_var_lib_t)
manage_sock_files_pattern(gitea_t, gitea_var_lib_t, gitea_var_lib_t)
files_var_lib_filetrans(gitea_t, gitea_var_lib_t, { dir file })
allow gitea_t gitea_log_t:dir { add_entry_dir_perms list_dir_perms };
create_files_pattern(gitea_t, gitea_log_t, gitea_log_t)
append_files_pattern(gitea_t, gitea_log_t, gitea_log_t)
setattr_files_pattern(gitea_t, gitea_log_t, gitea_log_t)
logging_log_filetrans(gitea_t, gitea_log_t, { dir file })

########################################
# Network
########################################
allow gitea_t self:tcp_socket create_stream_socket_perms;
allow gitea_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(gitea_t)
corenet_udp_bind_generic_node(gitea_t)
allow gitea_t gitea_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type sysctl_net_t;
')
allow gitea_t gitea_conf_t:file { setattr write };
allow gitea_t gitea_t:process setpgid;
allow gitea_t gitea_var_lib_t:file map;
allow gitea_t sysctl_net_t:dir search;
allow gitea_t sysctl_net_t:file { open read };
```

## File contexts (.fc)

```
/opt/gitea/bin/gitea	--	gen_context(system_u:object_r:gitea_exec_t,s0)
/etc/gitea(/.*)?	gen_context(system_u:object_r:gitea_conf_t,s0)
/var/lib/gitea(/.*)?	gen_context(system_u:object_r:gitea_var_lib_t,s0)
/var/log/gitea(/.*)?	gen_context(system_u:object_r:gitea_log_t,s0)
```
