# node_exporter — SELinux confinement report

- License class: open-source (Apache-2.0)
- Source: https://github.com/prometheus/node_exporter/releases (linux-arm64 tarball)
- Domain: `node_exporter_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 17 | 10 | 0 | ✅ |
| 2 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `node_exporter_t`: ✅
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

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/node_exporter-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(node_exporter, 1.0.0)

type node_exporter_t;
type node_exporter_exec_t;
init_daemon_domain(node_exporter_t, node_exporter_exec_t)

type node_exporter_port_t;
corenet_port(node_exporter_port_t)

########################################
# Base daemon rules
########################################
allow node_exporter_t self:process { fork signal signull sigkill getsched setsched };
allow node_exporter_t self:fifo_file rw_fifo_file_perms;
allow node_exporter_t self:unix_stream_socket create_stream_socket_perms;
allow node_exporter_t self:unix_dgram_socket create_socket_perms;
can_exec(node_exporter_t, node_exporter_exec_t)
kernel_read_system_state(node_exporter_t)
corecmd_exec_bin(node_exporter_t)
corecmd_exec_shell(node_exporter_t)
libs_exec_ldconfig(node_exporter_t)
miscfiles_read_localization(node_exporter_t)
miscfiles_read_generic_certs(node_exporter_t)
logging_send_syslog_msg(node_exporter_t)
files_read_etc_files(node_exporter_t)
files_read_usr_files(node_exporter_t)
fs_getattr_all_fs(node_exporter_t)
dev_read_urand(node_exporter_t)
dev_read_rand(node_exporter_t)
dev_read_sysfs(node_exporter_t)
auth_use_nsswitch(node_exporter_t)

########################################
# App file access
########################################

########################################
# Network
########################################
allow node_exporter_t self:tcp_socket create_stream_socket_perms;
allow node_exporter_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(node_exporter_t)
corenet_udp_bind_generic_node(node_exporter_t)
allow node_exporter_t node_exporter_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type proc_mdstat_t;
	type proc_net_t;
	type sysctl_fs_t;
	type sysctl_net_t;
	type sysctl_rpc_t;
	type udev_var_run_t;
')
allow node_exporter_t proc_mdstat_t:file { getattr open read };
allow node_exporter_t proc_net_t:dir search;
allow node_exporter_t proc_net_t:file { open read };
allow node_exporter_t proc_net_t:lnk_file read;
allow node_exporter_t sysctl_fs_t:dir search;
allow node_exporter_t sysctl_fs_t:file { open read };
allow node_exporter_t sysctl_net_t:dir search;
allow node_exporter_t sysctl_net_t:file { getattr open read };
allow node_exporter_t sysctl_rpc_t:dir search;
allow node_exporter_t udev_var_run_t:file { open read };
```

## File contexts (.fc)

```
/opt/node_exporter/bin/node_exporter	--	gen_context(system_u:object_r:node_exporter_exec_t,s0)
```
