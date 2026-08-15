# minio — SELinux confinement report

- License class: open-source (AGPL-3.0)
- Source: https://dl.min.io/server/minio/release/linux-arm64/minio
- Domain: `minio_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 6 | 4 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `minio_t`: ✅
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

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/minio-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(minio, 1.0.0)

type minio_t;
type minio_exec_t;
init_daemon_domain(minio_t, minio_exec_t)

type minio_var_lib_t;
files_type(minio_var_lib_t)
type minio_port_t;
corenet_port(minio_port_t)

########################################
# Base daemon rules
########################################
allow minio_t self:process { fork signal signull sigkill getsched setsched };
allow minio_t self:fifo_file rw_fifo_file_perms;
allow minio_t self:unix_stream_socket create_stream_socket_perms;
allow minio_t self:unix_dgram_socket create_socket_perms;
can_exec(minio_t, minio_exec_t)
kernel_read_system_state(minio_t)
corecmd_exec_bin(minio_t)
corecmd_exec_shell(minio_t)
libs_exec_ldconfig(minio_t)
miscfiles_read_localization(minio_t)
miscfiles_read_generic_certs(minio_t)
logging_send_syslog_msg(minio_t)
files_read_etc_files(minio_t)
files_read_usr_files(minio_t)
fs_getattr_all_fs(minio_t)
dev_read_urand(minio_t)
dev_read_rand(minio_t)
dev_read_sysfs(minio_t)
auth_use_nsswitch(minio_t)

########################################
# App file access
########################################
manage_dirs_pattern(minio_t, minio_var_lib_t, minio_var_lib_t)
manage_files_pattern(minio_t, minio_var_lib_t, minio_var_lib_t)
manage_lnk_files_pattern(minio_t, minio_var_lib_t, minio_var_lib_t)
manage_sock_files_pattern(minio_t, minio_var_lib_t, minio_var_lib_t)
files_var_lib_filetrans(minio_t, minio_var_lib_t, { dir file })

########################################
# Network
########################################
allow minio_t self:tcp_socket create_stream_socket_perms;
allow minio_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(minio_t)
corenet_udp_bind_generic_node(minio_t)
allow minio_t minio_port_t:tcp_socket name_bind;
allow minio_t minio_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type http_port_t;
	type proc_net_t;
	type sysctl_net_t;
')
allow minio_t http_port_t:tcp_socket name_connect;
allow minio_t proc_net_t:file { open read };
allow minio_t sysctl_net_t:dir search;
allow minio_t sysctl_net_t:file { open read };
```

## File contexts (.fc)

```
/opt/minio/bin/minio	--	gen_context(system_u:object_r:minio_exec_t,s0)
/var/lib/minio(/.*)?	gen_context(system_u:object_r:minio_var_lib_t,s0)
```
