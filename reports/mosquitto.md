# mosquitto — SELinux confinement report

- License class: open-source (EPL-2.0)
- Source: EPEL 9 RPM (mosquitto)
- Domain: `mosquitto_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 2 | 1 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `mosquitto_t`: ✅
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

- privileged capability: setgid — `allow mosquitto_t mosquitto_t:capability { setgid setuid };`

## Artifact

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/mosquitto-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(mosquitto, 1.0.0)

type mosquitto_t;
type mosquitto_exec_t;
init_daemon_domain(mosquitto_t, mosquitto_exec_t)

type mosquitto_conf_t;
files_config_file(mosquitto_conf_t)
type mosquitto_var_lib_t;
files_type(mosquitto_var_lib_t)
type mosquitto_log_t;
logging_log_file(mosquitto_log_t)
type mosquitto_port_t;
corenet_port(mosquitto_port_t)

########################################
# Base daemon rules
########################################
allow mosquitto_t self:process { fork signal signull sigkill getsched setsched };
allow mosquitto_t self:fifo_file rw_fifo_file_perms;
allow mosquitto_t self:unix_stream_socket create_stream_socket_perms;
allow mosquitto_t self:unix_dgram_socket create_socket_perms;
can_exec(mosquitto_t, mosquitto_exec_t)
kernel_read_system_state(mosquitto_t)
corecmd_exec_bin(mosquitto_t)
corecmd_exec_shell(mosquitto_t)
libs_exec_ldconfig(mosquitto_t)
miscfiles_read_localization(mosquitto_t)
miscfiles_read_generic_certs(mosquitto_t)
logging_send_syslog_msg(mosquitto_t)
files_read_etc_files(mosquitto_t)
files_read_usr_files(mosquitto_t)
fs_getattr_all_fs(mosquitto_t)
dev_read_urand(mosquitto_t)
dev_read_rand(mosquitto_t)
dev_read_sysfs(mosquitto_t)
auth_use_nsswitch(mosquitto_t)

########################################
# App file access
########################################
allow mosquitto_t mosquitto_conf_t:dir list_dir_perms;
read_files_pattern(mosquitto_t, mosquitto_conf_t, mosquitto_conf_t)
read_lnk_files_pattern(mosquitto_t, mosquitto_conf_t, mosquitto_conf_t)
manage_dirs_pattern(mosquitto_t, mosquitto_var_lib_t, mosquitto_var_lib_t)
manage_files_pattern(mosquitto_t, mosquitto_var_lib_t, mosquitto_var_lib_t)
manage_lnk_files_pattern(mosquitto_t, mosquitto_var_lib_t, mosquitto_var_lib_t)
manage_sock_files_pattern(mosquitto_t, mosquitto_var_lib_t, mosquitto_var_lib_t)
files_var_lib_filetrans(mosquitto_t, mosquitto_var_lib_t, { dir file })
allow mosquitto_t mosquitto_log_t:dir { add_entry_dir_perms list_dir_perms };
create_files_pattern(mosquitto_t, mosquitto_log_t, mosquitto_log_t)
append_files_pattern(mosquitto_t, mosquitto_log_t, mosquitto_log_t)
setattr_files_pattern(mosquitto_t, mosquitto_log_t, mosquitto_log_t)
logging_log_filetrans(mosquitto_t, mosquitto_log_t, { dir file })

########################################
# Network
########################################
allow mosquitto_t self:tcp_socket create_stream_socket_perms;
allow mosquitto_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(mosquitto_t)
corenet_udp_bind_generic_node(mosquitto_t)
allow mosquitto_t mosquitto_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
allow mosquitto_t mosquitto_t:capability { setgid setuid };
```

## File contexts (.fc)

```
/usr/sbin/mosquitto	--	gen_context(system_u:object_r:mosquitto_exec_t,s0)
/etc/mosquitto(/.*)?	gen_context(system_u:object_r:mosquitto_conf_t,s0)
/var/lib/mosquitto(/.*)?	gen_context(system_u:object_r:mosquitto_var_lib_t,s0)
/var/log/mosquitto(/.*)?	gen_context(system_u:object_r:mosquitto_log_t,s0)
```
