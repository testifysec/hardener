# victoria-metrics — SELinux confinement report

- License class: open-source (Apache-2.0)
- Source: https://github.com/VictoriaMetrics/VictoriaMetrics/releases (linux-arm64 tarball)
- Domain: `victoria_metrics_t`

**Overall: PASS**

## Observation rounds (permissive domain)

| Round | Denials | New rules | Relabels | Exercise |
|---|---|---|---|---|
| 1 | 3 | 2 | 0 | ✅ |
| 2 | 1 | 1 | 0 | ✅ |
| 3 | 0 | 0 | 0 | ✅ |

## Enforcing verification

- Process runs in `victoria_metrics_t`: ✅
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

- `/home/nkennedy.guest/rpmbuild/RPMS/noarch/victoria_metrics-selinux-1.0.0-1.el9.noarch.rpm`

## Generated policy (.te)

```
policy_module(victoria_metrics, 1.0.0)

type victoria_metrics_t;
type victoria_metrics_exec_t;
init_daemon_domain(victoria_metrics_t, victoria_metrics_exec_t)

type victoria_metrics_var_lib_t;
files_type(victoria_metrics_var_lib_t)
type victoria_metrics_port_t;
corenet_port(victoria_metrics_port_t)

########################################
# Base daemon rules
########################################
allow victoria_metrics_t self:process { fork signal signull sigkill getsched setsched };
allow victoria_metrics_t self:fifo_file rw_fifo_file_perms;
allow victoria_metrics_t self:unix_stream_socket create_stream_socket_perms;
allow victoria_metrics_t self:unix_dgram_socket create_socket_perms;
can_exec(victoria_metrics_t, victoria_metrics_exec_t)
kernel_read_system_state(victoria_metrics_t)
corecmd_exec_bin(victoria_metrics_t)
corecmd_exec_shell(victoria_metrics_t)
libs_exec_ldconfig(victoria_metrics_t)
miscfiles_read_localization(victoria_metrics_t)
miscfiles_read_generic_certs(victoria_metrics_t)
logging_send_syslog_msg(victoria_metrics_t)
files_read_etc_files(victoria_metrics_t)
files_read_usr_files(victoria_metrics_t)
fs_getattr_all_fs(victoria_metrics_t)
dev_read_urand(victoria_metrics_t)
dev_read_rand(victoria_metrics_t)
dev_read_sysfs(victoria_metrics_t)
auth_use_nsswitch(victoria_metrics_t)

########################################
# App file access
########################################
manage_dirs_pattern(victoria_metrics_t, victoria_metrics_var_lib_t, victoria_metrics_var_lib_t)
manage_files_pattern(victoria_metrics_t, victoria_metrics_var_lib_t, victoria_metrics_var_lib_t)
manage_lnk_files_pattern(victoria_metrics_t, victoria_metrics_var_lib_t, victoria_metrics_var_lib_t)
manage_sock_files_pattern(victoria_metrics_t, victoria_metrics_var_lib_t, victoria_metrics_var_lib_t)
files_var_lib_filetrans(victoria_metrics_t, victoria_metrics_var_lib_t, { dir file })

########################################
# Network
########################################
allow victoria_metrics_t self:tcp_socket create_stream_socket_perms;
allow victoria_metrics_t self:udp_socket create_socket_perms;
corenet_tcp_bind_generic_node(victoria_metrics_t)
corenet_udp_bind_generic_node(victoria_metrics_t)
allow victoria_metrics_t victoria_metrics_port_t:tcp_socket name_bind;

########################################
# Observed refinements
########################################
gen_require(`
	type sysctl_net_t;
')
allow victoria_metrics_t sysctl_net_t:dir search;
allow victoria_metrics_t sysctl_net_t:file { open read };
allow victoria_metrics_t victoria_metrics_var_lib_t:file map;
```

## File contexts (.fc)

```
/opt/victoria-metrics/bin/victoria-metrics-prod	--	gen_context(system_u:object_r:victoria_metrics_exec_t,s0)
/var/lib/victoria-metrics(/.*)?	gen_context(system_u:object_r:victoria_metrics_var_lib_t,s0)
```
