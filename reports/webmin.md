# webmin — SELinux confinement report

- License class: open-source (BSD-3-Clause)
- Source: https://github.com/webmin/webmin/releases (noarch RPM — 25-year-old perl codebase)
- Domain: `webmin_t`

**Overall: PASS (with accepted exceptions)**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 106 | 52 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `webmin_t`: ✅
- Exercise passes under Enforcing: ✅
- Residual AVC denials: 0

## Static least-privilege checks

- no etc_t write: ✅
- no sys_admin capability: ✅
- no sys_module capability: ✅
- no kernel module load: ✅
- not permissive: ✅
- no selinux mgmt: ✅

## ⚠ Accepted exceptions (least-privilege deviations, consciously granted)

- no shadow_t read/write — `allow webmin_t shadow_t:file { getattr open read };`

## ⚠ Rules requiring human review

- privileged capability: dac_read_search — `allow webmin_t webmin_t:capability dac_read_search;`
- sensitive target type: shadow_t — `allow webmin_t shadow_t:file { getattr open read };`
- broad shared type (grants access to other applications' files): var_log_t — `allow webmin_t var_log_t:file { create open read setattr unlink write };`
- broad shared type (grants access to other applications' files): var_log_t — `allow webmin_t var_log_t:dir { add_name create remove_name rmdir setattr write };`
- broad shared type (grants access to other applications' files): var_log_t — `allow webmin_t var_log_t:lnk_file create;`
- sensitive target type: kernel_t — `allow webmin_t kernel_t:file { open read };`

## Coverage cross-check (static import analysis)

Entrypoints are statically linked; import-based prediction unavailable (syscall-site disassembly is the follow-up for this case).

## ⚠ Base-policy path collisions

These paths are already claimed by the distro policy. hardener does not redeclare them (semodule would reject the module), so the application's files there keep the base label:

- /var/webmin(/.*)? already claimed by base policy as var_log_t (wanted webmin_var_lib_t)

## Artifact

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/webmin-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(webmin, 1.0.0)

type webmin_t;
type webmin_exec_t;
init_daemon_domain(webmin_t, webmin_exec_t)

type webmin_conf_t;
files_config_file(webmin_conf_t)
type webmin_content_t;
files_type(webmin_content_t)
type webmin_port_t;
corenet_port(webmin_port_t)

########################################
# Base daemon rules
########################################
allow webmin_t self:process { fork signal signull sigkill getsched setsched };
allow webmin_t self:fifo_file rw_fifo_file_perms;
allow webmin_t self:unix_stream_socket create_stream_socket_perms;
allow webmin_t self:unix_dgram_socket create_socket_perms;
can_exec(webmin_t, webmin_exec_t)
kernel_read_system_state(webmin_t)
corecmd_exec_bin(webmin_t)
corecmd_exec_shell(webmin_t)
libs_exec_ldconfig(webmin_t)
miscfiles_read_localization(webmin_t)
miscfiles_read_generic_certs(webmin_t)
logging_send_syslog_msg(webmin_t)
files_read_etc_files(webmin_t)
files_read_usr_files(webmin_t)
fs_getattr_all_fs(webmin_t)
dev_read_urand(webmin_t)
dev_read_rand(webmin_t)
dev_read_sysfs(webmin_t)
auth_use_nsswitch(webmin_t)

########################################
# App file access
########################################
allow webmin_t webmin_conf_t:dir list_dir_perms;
read_files_pattern(webmin_t, webmin_conf_t, webmin_conf_t)
read_lnk_files_pattern(webmin_t, webmin_conf_t, webmin_conf_t)
manage_dirs_pattern(webmin_t, webmin_content_t, webmin_content_t)
manage_files_pattern(webmin_t, webmin_content_t, webmin_content_t)
manage_lnk_files_pattern(webmin_t, webmin_content_t, webmin_content_t)
manage_sock_files_pattern(webmin_t, webmin_content_t, webmin_content_t)

########################################
# Network
########################################
allow webmin_t self:tcp_socket create_stream_socket_perms;
allow webmin_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(webmin_t)
corenet_udp_bind_generic_node(webmin_t)
allow webmin_t webmin_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type NetworkManager_t;
	type auditd_t;
	type chronyd_t;
	type crond_t;
	type fixed_disk_device_t;
	type fsadm_exec_t;
	type getty_t;
	type gssproxy_t;
	type hostname_exec_t;
	type irqbalance_t;
	type iso9660_t;
	type kernel_t;
	type policykit_t;
	type rpcbind_t;
	type rpm_exec_t;
	type rpm_script_tmp_t;
	type shadow_t;
	type sshd_t;
	type syslogd_t;
	type system_cronjob_t;
	type system_dbusd_t;
	type systemd_hostnamed_t;
	type systemd_logind_t;
	type tuned_t;
	type udev_t;
	type unconfined_service_t;
	type unconfined_t;
	type unreserved_port_t;
	type var_log_t;
')
allow webmin_t NetworkManager_t:dir { getattr search };
allow webmin_t NetworkManager_t:file { open read };
allow webmin_t auditd_t:dir { getattr search };
allow webmin_t auditd_t:file { open read };
allow webmin_t chronyd_t:dir { getattr search };
allow webmin_t chronyd_t:file { open read };
allow webmin_t crond_t:dir { getattr search };
allow webmin_t crond_t:file { open read };
allow webmin_t fixed_disk_device_t:blk_file getattr;
allow webmin_t fsadm_exec_t:file getattr;
allow webmin_t getty_t:dir { getattr search };
allow webmin_t getty_t:file { open read };
allow webmin_t getty_t:lnk_file read;
allow webmin_t gssproxy_t:dir { getattr search };
allow webmin_t gssproxy_t:file { open read };
allow webmin_t hostname_exec_t:file { execute execute_no_trans getattr map open read };
allow webmin_t irqbalance_t:dir { getattr search };
allow webmin_t irqbalance_t:file { open read };
allow webmin_t iso9660_t:dir { getattr open read };
allow webmin_t kernel_t:dir { getattr search };
allow webmin_t kernel_t:file { open read };
allow webmin_t policykit_t:dir { getattr search };
allow webmin_t policykit_t:file { open read };
allow webmin_t rpcbind_t:dir { getattr search };
allow webmin_t rpcbind_t:file { open read };
allow webmin_t rpm_exec_t:file getattr;
allow webmin_t rpm_script_tmp_t:dir read;
allow webmin_t shadow_t:file { getattr open read };
allow webmin_t sshd_t:dir { getattr search };
allow webmin_t sshd_t:file { open read };
allow webmin_t syslogd_t:dir { getattr search };
allow webmin_t syslogd_t:file { open read };
allow webmin_t system_cronjob_t:dir { getattr search };
allow webmin_t system_cronjob_t:file { open read };
allow webmin_t system_dbusd_t:dir { getattr search };
allow webmin_t system_dbusd_t:file { open read };
allow webmin_t systemd_hostnamed_t:dir { getattr search };
allow webmin_t systemd_hostnamed_t:file { open read };
allow webmin_t systemd_logind_t:dir { getattr search };
allow webmin_t systemd_logind_t:file { open read };
allow webmin_t tuned_t:dir { getattr search };
allow webmin_t tuned_t:file { open read };
allow webmin_t udev_t:dir { getattr search };
allow webmin_t udev_t:file { open read };
allow webmin_t unconfined_service_t:dir { getattr search };
allow webmin_t unconfined_service_t:file { open read };
allow webmin_t unconfined_t:dir { getattr search };
allow webmin_t unconfined_t:file { open read };
allow webmin_t unreserved_port_t:udp_socket name_bind;
allow webmin_t var_log_t:dir { add_name create remove_name rmdir setattr write };
allow webmin_t var_log_t:file { create open read setattr unlink write };
allow webmin_t var_log_t:lnk_file create;
allow webmin_t webmin_t:cap_userns sys_ptrace;
allow webmin_t webmin_t:capability dac_read_search;
```

## File contexts (.fc)

```
/usr/libexec/webmin/miniserv\.pl	--	gen_context(system_u:object_r:webmin_exec_t,s0)
/etc/webmin(/.*)?	gen_context(system_u:object_r:webmin_conf_t,s0)
/usr/libexec/webmin(/.*)?	gen_context(system_u:object_r:webmin_content_t,s0)
```
