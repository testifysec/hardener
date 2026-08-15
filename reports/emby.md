# emby — SELinux confinement report

- License class: proprietary closed-source core — freely distributable
- Source: https://github.com/MediaBrowser/Emby.Releases (aarch64 RPM)
- Domain: `emby_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 33 | 14 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `emby_t`: ✅
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

## ⚠ Rules requiring human review

- broad shared type (grants access to other applications' files): tmp_t — `allow emby_t tmp_t:sock_file { create unlink };`
- broad shared type (grants access to other applications' files): tmp_t — `allow emby_t tmp_t:fifo_file { create open read unlink };`
- broad shared type (grants access to other applications' files): tmp_t — `allow emby_t tmp_t:dir { create rmdir setattr };`
- broad shared type (grants access to other applications' files): tmp_t — `allow emby_t tmp_t:file { create map open setattr unlink write };`

## Artifact

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/emby-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(emby, 1.0.0)

type emby_t;
type emby_exec_t;
init_daemon_domain(emby_t, emby_exec_t)

type emby_var_lib_t;
files_type(emby_var_lib_t)
type emby_content_t;
files_type(emby_content_t)
type emby_port_t;
corenet_port(emby_port_t)

########################################
# Base daemon rules
########################################
allow emby_t self:process { fork signal signull sigkill getsched setsched };
allow emby_t self:fifo_file rw_fifo_file_perms;
allow emby_t self:unix_stream_socket create_stream_socket_perms;
allow emby_t self:unix_dgram_socket create_socket_perms;
can_exec(emby_t, emby_exec_t)
kernel_read_system_state(emby_t)
corecmd_exec_bin(emby_t)
corecmd_exec_shell(emby_t)
libs_exec_ldconfig(emby_t)
miscfiles_read_localization(emby_t)
miscfiles_read_generic_certs(emby_t)
logging_send_syslog_msg(emby_t)
files_read_etc_files(emby_t)
files_read_usr_files(emby_t)
fs_getattr_all_fs(emby_t)
dev_read_urand(emby_t)
dev_read_rand(emby_t)
dev_read_sysfs(emby_t)
auth_use_nsswitch(emby_t)

########################################
# App file access
########################################
manage_dirs_pattern(emby_t, emby_var_lib_t, emby_var_lib_t)
manage_files_pattern(emby_t, emby_var_lib_t, emby_var_lib_t)
manage_lnk_files_pattern(emby_t, emby_var_lib_t, emby_var_lib_t)
manage_sock_files_pattern(emby_t, emby_var_lib_t, emby_var_lib_t)
manage_dirs_pattern(emby_t, emby_content_t, emby_content_t)
manage_files_pattern(emby_t, emby_content_t, emby_content_t)
manage_lnk_files_pattern(emby_t, emby_content_t, emby_content_t)
manage_sock_files_pattern(emby_t, emby_content_t, emby_content_t)
files_var_lib_filetrans(emby_t, emby_var_lib_t, { dir file })

########################################
# Network
########################################
allow emby_t self:tcp_socket create_stream_socket_perms;
allow emby_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(emby_t)
corenet_udp_bind_generic_node(emby_t)
allow emby_t emby_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type proc_net_t;
	type ssdp_port_t;
	type sysctl_net_t;
	type tmp_t;
	type unreserved_port_t;
')
allow emby_t emby_content_t:file { execute execute_no_trans map };
allow emby_t emby_port_t:tcp_socket name_connect;
allow emby_t emby_t:process { execmem getsession };
allow emby_t emby_var_lib_t:file map;
allow emby_t proc_net_t:file { getattr lock open read };
allow emby_t proc_net_t:lnk_file read;
allow emby_t ssdp_port_t:udp_socket name_bind;
allow emby_t sysctl_net_t:dir search;
allow emby_t sysctl_net_t:file { getattr lock open read };
allow emby_t tmp_t:dir { create rmdir setattr };
allow emby_t tmp_t:fifo_file { create open read unlink };
allow emby_t tmp_t:file { create map open setattr unlink write };
allow emby_t tmp_t:sock_file { create unlink };
allow emby_t unreserved_port_t:udp_socket name_bind;
```

## File contexts (.fc)

```
/opt/emby-server/bin/emby-server	--	gen_context(system_u:object_r:emby_exec_t,s0)
/opt/emby-server/system/EmbyServer	--	gen_context(system_u:object_r:emby_exec_t,s0)
/opt/emby-server(/.*)?	gen_context(system_u:object_r:emby_content_t,s0)
/var/lib/emby(/.*)?	gen_context(system_u:object_r:emby_var_lib_t,s0)
```
