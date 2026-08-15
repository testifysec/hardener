# vault — SELinux confinement report

- License class: source-available, NOT open source (BSL 1.1) — freely distributable
- Source: https://releases.hashicorp.com/vault/ (linux_arm64 zip)
- Domain: `vault_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 3 | 2 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `vault_t`: ✅
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

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/vault-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(vault, 1.0.0)

type vault_t;
type vault_exec_t;
init_daemon_domain(vault_t, vault_exec_t)

type vault_conf_t;
files_config_file(vault_conf_t)
type vault_var_lib_t;
files_type(vault_var_lib_t)
type vault_port_t;
corenet_port(vault_port_t)

########################################
# Base daemon rules
########################################
allow vault_t self:process { fork signal signull sigkill getsched setsched };
allow vault_t self:fifo_file rw_fifo_file_perms;
allow vault_t self:unix_stream_socket create_stream_socket_perms;
allow vault_t self:unix_dgram_socket create_socket_perms;
can_exec(vault_t, vault_exec_t)
kernel_read_system_state(vault_t)
corecmd_exec_bin(vault_t)
corecmd_exec_shell(vault_t)
libs_exec_ldconfig(vault_t)
miscfiles_read_localization(vault_t)
miscfiles_read_generic_certs(vault_t)
logging_send_syslog_msg(vault_t)
files_read_etc_files(vault_t)
files_read_usr_files(vault_t)
fs_getattr_all_fs(vault_t)
dev_read_urand(vault_t)
dev_read_rand(vault_t)
dev_read_sysfs(vault_t)
auth_use_nsswitch(vault_t)

########################################
# App file access
########################################
allow vault_t vault_conf_t:dir list_dir_perms;
read_files_pattern(vault_t, vault_conf_t, vault_conf_t)
read_lnk_files_pattern(vault_t, vault_conf_t, vault_conf_t)
manage_dirs_pattern(vault_t, vault_var_lib_t, vault_var_lib_t)
manage_files_pattern(vault_t, vault_var_lib_t, vault_var_lib_t)
manage_lnk_files_pattern(vault_t, vault_var_lib_t, vault_var_lib_t)
manage_sock_files_pattern(vault_t, vault_var_lib_t, vault_var_lib_t)
files_var_lib_filetrans(vault_t, vault_var_lib_t, { dir file })

########################################
# Network
########################################
allow vault_t self:tcp_socket create_stream_socket_perms;
allow vault_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(vault_t)
corenet_udp_bind_generic_node(vault_t)
allow vault_t vault_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type sysctl_net_t;
')
allow vault_t sysctl_net_t:dir search;
allow vault_t sysctl_net_t:file { open read };
```

## File contexts (.fc)

```
/opt/vault/bin/vault	--	gen_context(system_u:object_r:vault_exec_t,s0)
/etc/vault(/.*)?	gen_context(system_u:object_r:vault_conf_t,s0)
/var/lib/vault(/.*)?	gen_context(system_u:object_r:vault_var_lib_t,s0)
```
