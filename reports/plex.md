# plex — SELinux confinement report

- License class: proprietary closed-source — freely distributable installer
- Source: https://plex.tv/api/downloads/5.json (aarch64 ships only as .deb — payload extracted onto RHEL, the classic foreign-artifact case)
- Domain: `plex_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 84 | 52 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `plex_t`: ✅
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

- broad shared type (grants access to other applications' files): tmp_t — `allow plex_t tmp_t:dir { create rmdir };`
- broad shared type (grants access to other applications' files): tmp_t — `allow plex_t tmp_t:file { create execute map open unlink write };`
- sensitive target type: kernel_t — `allow plex_t kernel_t:file { open read };`

## Coverage cross-check (static import analysis)

- `dns-resolve` (imports getaddrinfo)
- `exec-other` (imports execve, popen, system)
- `file-unlink` (imports unlink)
- `fork` (imports fork)
- `outbound-connect` (imports connect)
- `port-bind` (imports accept, bind, listen)

## Artifact

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/plex-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(plex, 1.0.0)

type plex_t;
type plex_exec_t;
init_daemon_domain(plex_t, plex_exec_t)

type plex_var_lib_t;
files_type(plex_var_lib_t)
type plex_content_t;
files_type(plex_content_t)
type plex_port_t;
corenet_port(plex_port_t)

########################################
# Base daemon rules
########################################
allow plex_t self:process { fork signal signull sigkill getsched setsched };
allow plex_t self:fifo_file rw_fifo_file_perms;
allow plex_t self:unix_stream_socket create_stream_socket_perms;
allow plex_t self:unix_dgram_socket create_socket_perms;
can_exec(plex_t, plex_exec_t)
kernel_read_system_state(plex_t)
corecmd_exec_bin(plex_t)
corecmd_exec_shell(plex_t)
libs_exec_ldconfig(plex_t)
miscfiles_read_localization(plex_t)
miscfiles_read_generic_certs(plex_t)
logging_send_syslog_msg(plex_t)
files_read_etc_files(plex_t)
files_read_usr_files(plex_t)
fs_getattr_all_fs(plex_t)
dev_read_urand(plex_t)
dev_read_rand(plex_t)
dev_read_sysfs(plex_t)
auth_use_nsswitch(plex_t)

########################################
# App file access
########################################
manage_dirs_pattern(plex_t, plex_var_lib_t, plex_var_lib_t)
manage_files_pattern(plex_t, plex_var_lib_t, plex_var_lib_t)
manage_lnk_files_pattern(plex_t, plex_var_lib_t, plex_var_lib_t)
manage_sock_files_pattern(plex_t, plex_var_lib_t, plex_var_lib_t)
manage_dirs_pattern(plex_t, plex_content_t, plex_content_t)
manage_files_pattern(plex_t, plex_content_t, plex_content_t)
manage_lnk_files_pattern(plex_t, plex_content_t, plex_content_t)
manage_sock_files_pattern(plex_t, plex_content_t, plex_content_t)
files_var_lib_filetrans(plex_t, plex_var_lib_t, { dir file })

########################################
# Network
########################################
allow plex_t self:tcp_socket create_stream_socket_perms;
allow plex_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(plex_t)
corenet_udp_bind_generic_node(plex_t)
allow plex_t plex_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type NetworkManager_t;
	type auditd_t;
	type chronyd_t;
	type crond_t;
	type ephemeral_port_t;
	type getty_t;
	type gssproxy_t;
	type http_port_t;
	type irqbalance_t;
	type kernel_t;
	type policykit_t;
	type proc_net_t;
	type rpcbind_t;
	type sshd_t;
	type syslogd_t;
	type system_cronjob_t;
	type system_dbusd_t;
	type systemd_hostnamed_t;
	type systemd_logind_t;
	type tmp_t;
	type tmpfs_t;
	type tuned_t;
	type udev_t;
	type unconfined_service_t;
	type unconfined_t;
	type unreserved_port_t;
')
allow plex_t NetworkManager_t:dir search;
allow plex_t NetworkManager_t:file { open read };
allow plex_t auditd_t:dir search;
allow plex_t auditd_t:file { open read };
allow plex_t chronyd_t:dir search;
allow plex_t chronyd_t:file { open read };
allow plex_t crond_t:dir search;
allow plex_t crond_t:file { open read };
allow plex_t ephemeral_port_t:tcp_socket name_connect;
allow plex_t getty_t:dir search;
allow plex_t getty_t:file { open read };
allow plex_t gssproxy_t:dir search;
allow plex_t gssproxy_t:file { open read };
allow plex_t http_port_t:tcp_socket name_connect;
allow plex_t irqbalance_t:dir search;
allow plex_t irqbalance_t:file { open read };
allow plex_t kernel_t:dir search;
allow plex_t kernel_t:file { open read };
allow plex_t plex_content_t:file { execute map };
allow plex_t plex_port_t:tcp_socket name_connect;
allow plex_t plex_var_lib_t:file map;
allow plex_t policykit_t:dir search;
allow plex_t policykit_t:file { open read };
allow plex_t proc_net_t:file { open read };
allow plex_t proc_net_t:lnk_file read;
allow plex_t rpcbind_t:dir search;
allow plex_t rpcbind_t:file { open read };
allow plex_t sshd_t:dir search;
allow plex_t sshd_t:file { open read };
allow plex_t syslogd_t:dir search;
allow plex_t syslogd_t:file { open read };
allow plex_t system_cronjob_t:dir search;
allow plex_t system_cronjob_t:file { open read };
allow plex_t system_dbusd_t:dir search;
allow plex_t system_dbusd_t:file { open read };
allow plex_t systemd_hostnamed_t:dir search;
allow plex_t systemd_hostnamed_t:file { open read };
allow plex_t systemd_logind_t:dir search;
allow plex_t systemd_logind_t:file { open read };
allow plex_t tmp_t:dir { create rmdir };
allow plex_t tmp_t:file { create execute map open unlink write };
allow plex_t tmpfs_t:file { create getattr link map open read unlink write };
allow plex_t tuned_t:dir search;
allow plex_t tuned_t:file { open read };
allow plex_t udev_t:dir search;
allow plex_t udev_t:file { open read };
allow plex_t unconfined_service_t:dir search;
allow plex_t unconfined_service_t:file { open read };
allow plex_t unconfined_t:dir search;
allow plex_t unconfined_t:file { open read };
allow plex_t unreserved_port_t:tcp_socket name_bind;
allow plex_t unreserved_port_t:udp_socket name_bind;
```

## File contexts (.fc)

```
/usr/lib/plexmediaserver/Plex\sMedia\sServer	--	gen_context(system_u:object_r:plex_exec_t,s0)
/usr/lib/plexmediaserver/Plex\sScript\sHost	--	gen_context(system_u:object_r:plex_exec_t,s0)
/usr/lib/plexmediaserver/Plex\sMedia\sScanner	--	gen_context(system_u:object_r:plex_exec_t,s0)
/usr/lib/plexmediaserver/Plex\sTuner\sService	--	gen_context(system_u:object_r:plex_exec_t,s0)
/usr/lib/plexmediaserver(/.*)?	gen_context(system_u:object_r:plex_content_t,s0)
/var/lib/plexmediaserver(/.*)?	gen_context(system_u:object_r:plex_var_lib_t,s0)
```
