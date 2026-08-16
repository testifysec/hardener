package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/testifysec/hardener/internal/avc"
	"github.com/testifysec/hardener/internal/profile"
)

// AllowRule is one synthesized allow rule.
type AllowRule struct {
	Source string
	Target string
	Class  string
	Perms  []string
}

// Render emits the rule in .te syntax with perms in sorted order.
func (r AllowRule) Render() string {
	perms := append([]string(nil), r.Perms...)
	sort.Strings(perms)
	if len(perms) == 1 {
		return fmt.Sprintf("allow %s %s:%s %s;", r.Source, r.Target, r.Class, perms[0])
	}
	return fmt.Sprintf("allow %s %s:%s { %s };", r.Source, r.Target, r.Class, strings.Join(perms, " "))
}

// Relabel records a file whose on-disk label diverges from our file contexts.
// The fix is restorecon, not policy.
type Relabel struct {
	Path         string
	ObservedType string
	ExpectedType string
}

// Flag marks a rule or relabel that needs human security review before shipping.
type Flag struct {
	Reason string
	Rule   AllowRule
}

// EntrypointIssue records that some other domain (normally init_t) was denied
// execute on a file we labeled as ordinary content. That file is really an
// entrypoint: without the exec label the domain transition cannot happen and
// the service never starts — while the confined domain reports no denials at
// all, because it never ran.
type EntrypointIssue struct {
	Name         string
	SourceType   string
	ObservedType string
}

// Refinement is the outcome of analyzing one round of AVC denials.
type Refinement struct {
	AllowRules  []AllowRule
	Relabels    []Relabel
	Flags       []Flag
	Entrypoints []EntrypointIssue
}

// writableOwnedSuffixes are the app's own WRITABLE data types. Executing from any
// of them is a W^X violation worth review.
var writableOwnedSuffixes = []string{"_var_lib_t", "_log_t", "_runtime_t", "_tmp_t", "_cache_t"}

// unionPerms returns the sorted, de-duplicated union of two permission sets.
func unionPerms(a, b []string) []string {
	seen := map[string]bool{}
	for _, p := range a {
		seen[p] = true
	}
	for _, p := range b {
		seen[p] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// isWritableOwnedType reports whether t is one of the app's writable data types.
func isWritableOwnedType(t string) bool {
	for _, s := range writableOwnedSuffixes {
		if strings.HasSuffix(t, s) {
			return true
		}
	}
	return false
}

// safeForeignTypes is the curated allowlist of distro types a confined daemon
// routinely reads with no meaningful risk. Everything else foreign goes to
// review by default — the set of dangerous types is open-ended, so an
// allowlist is the only fail-closed posture. cert_t is deliberately NOT here:
// it labels TLS PRIVATE KEYS as well as public certs (/etc/pki/tls/private), so
// auto-allowing reads would let a confined daemon read other services' keys —
// it must go to review (review finding).
var safeForeignTypes = map[string]bool{
	"sysctl_net_t":      true, // /proc/sys/net tunables
	"sysctl_kernel_t":   true, // read-only kernel tunables
	"net_conf_t":        true, // /etc/resolv.conf, hosts
	"hostname_exec_t":   true, // running /usr/bin/hostname
	"ldconfig_exec_t":   true, // dynamic loader cache refresh
	"locale_t":          true, // localization data
	"proc_t":            true, // /proc
	"proc_net_t":        true, // /proc/net
	"random_device_t":   true, // /dev/random, urandom
	"devlog_t":          true, // /dev/log syslog socket
	"syslogd_var_run_t": true, // syslog runtime socket dir
}

// safeCapabilities is the ALLOWLIST: capabilities a confined daemon may hold
// without human review. Everything else is privilege worth a look — a
// blocklist silently passed audit_control, bpf, perfmon, setpcap, setfcap,
// and every future capability (review finding). net_bind_service (bind a port
// below 1024) is the one routine, low-blast-radius capability.
var safeCapabilities = map[string]bool{
	"net_bind_service": true,
}

// safeProcessPerms is a fail-closed ALLOWLIST of process/process2 permissions a
// normal daemon needs on ITSELF. Everything else — setexec, setcurrent,
// setfscreate, setkeycreate, setsockcreate, setcap, execmem/execstack/execheap,
// ptrace, dyntransition, ... — is a context/process-manipulation privilege that
// must go to human review. A blocklist missed those (same-domain targets count
// as owned, so they bypassed the foreign-type gate and auto-emitted) (review
// finding).
var safeProcessPerms = map[string]bool{
	"fork": true, "sigchld": true, "sigkill": true, "sigstop": true,
	"signull": true, "signal": true, "getsched": true, "setsched": true,
	"getpgid": true, "setpgid": true, "getsession": true, "getcap": true,
	"share": true, "getattr": true, "setrlimit": true, "getrlimit": true,
	"noatsecure": true, "siginh": true, "rlimitinh": true, "transition": true,
}

var dangerousTargets = map[string]bool{
	"shadow_t": true, "etc_t": true, "security_t": true, "kernel_t": true,
	"init_t": true, "memory_device_t": true, "fixed_disk_device_t": true,
	"selinux_config_t": true, "auth_cache_t": true, "sysctl_t": true,
}

// dangerousClasses are kernel object classes that grant capabilities far beyond
// file access — a confined daemon almost never legitimately needs them, and each
// is a well-known privilege-escalation / sandbox-escape surface. Any denial of
// these classes goes to review regardless of target ownership.
var dangerousClasses = map[string]bool{
	"bpf": true, "perf_event": true, "io_uring": true,
	// memprotect governs process memory protections — mmap_zero (map the NULL
	// page) is a classic kernel-exploit primitive.
	"memprotect": true,
}

// safeSelfTargetClasses is a FAIL-CLOSED allowlist for a domain acting on ITSELF
// (source == target). The base template already grants the common self classes,
// so a self-target DENIAL is for something not pre-granted; only these plainly
// benign classes (own files/fds, the standard socket + SysV-IPC primitives, own
// keyring) auto-apply. Any OTHER self-target class — memprotect, an exotic
// socket, an unknown future class — defaults to review rather than silently
// shipping, since the foreign-type gate never sees an owned self-target.
// Capability/process classes are handled by dangerReason's dedicated allowlists
// and are intentionally omitted here.
var safeSelfTargetClasses = map[string]bool{
	"file": true, "dir": true, "lnk_file": true, "sock_file": true,
	"fifo_file": true, "chr_file": true, "blk_file": true, "fd": true,
	"unix_stream_socket": true, "unix_dgram_socket": true,
	"tcp_socket": true, "udp_socket": true,
	"netlink_route_socket": true, "netlink_socket": true,
	"packet_socket": true, "rawip_socket": true,
	"sem": true, "shm": true, "msg": true, "msgq": true, "key": true,
}

// genericTargets are broad shared types owned by no single application.
// Granting a confined domain access to one re-opens access to every other
// application's files carrying that label — the precise over-permission
// audit2allow produces. Always route these to human review.
var genericTargets = map[string]bool{
	"var_log_t": true, "var_lib_t": true, "var_t": true, "tmp_t": true,
	"default_t": true, "usr_t": true, "var_run_t": true, "unlabeled_t": true,
	"file_t": true, "home_root_t": true, "user_home_t": true,
}

// Refine classifies a batch of denials into relabels (labeling drift under our
// own file-context claims) vs. genuine allow rules, flagging anything dangerous.
// This is the discrimination step audit2allow does not do.
func Refine(p *profile.Profile, denials []avc.Denial) Refinement {
	dom := DomainType(p.Name)
	res := Refinement{}
	matchers := compileFCMatchers(p)

	own := ownTypes(p)
	matchersEarly := matchers
	// Classify labeling drift PER-DENIAL before merging: merging erases the
	// per-path evidence, and a mislabeled file merged with a genuine foreign
	// access would emit a type-wide allow rule covering both.
	var remaining []avc.Denial
	for _, d := range denials {
		if d.SourceType == dom && isFileClass(d.Class) {
			if exp, ok := expectedType(matchersEarly, d.Path); ok && exp != d.TargetType {
				res.Relabels = append(res.Relabels, Relabel{
					Path: d.Path, ObservedType: d.TargetType, ExpectedType: exp,
				})
				continue
			}
		}
		// Classify mislabeled ENTRYPOINTS per-denial too, BEFORE merging: a launcher
		// domain (init_t) denied execute on one of our non-exec owned types means we
		// labeled an entrypoint as content instead of _exec_t. avc.Merge erases the
		// path and collapses distinct entrypoints sharing source/target/class into
		// one, so detection must happen here, like relabels (review finding).
		if isLauncherDomain(d.SourceType) && own[d.TargetType] &&
			!strings.HasSuffix(d.TargetType, "_exec_t") &&
			isFileClass(d.Class) && hasPerm(d.Perms, "execute") {
			res.Entrypoints = append(res.Entrypoints, EntrypointIssue{
				Name: entrypointName(d), SourceType: d.SourceType, ObservedType: d.TargetType,
			})
			continue
		}
		remaining = append(remaining, d)
	}
	for _, d := range avc.Merge(remaining) {
		if d.SourceType != dom {
			// Entrypoint mislabels from a foreign launcher domain are now classified
			// per-denial BEFORE the merge (above); any other foreign-source denial is
			// another domain's business, not ours.
			continue
		}
		perms := d.Perms
		// Executing a helper requires the whole read+exec set; granting only
		// the observed perm makes each verification run surface one more
		// (getattr → read → open → map), costing a round per permission. UNION the
		// canonical set with the observed perms — REPLACING them dropped any other
		// observed permission (a `{ execute write }` denial lost `write`), hiding
		// dangerous behavior from the self-modification/danger checks below and the
		// signed result (review finding).
		if d.Class == "file" && strings.HasSuffix(d.TargetType, "_exec_t") && hasPerm(perms, "execute") {
			perms = unionPerms(perms, []string{"execute", "execute_no_trans", "getattr", "map", "open", "read"})
		}
		rule := AllowRule{Source: dom, Target: d.TargetType, Class: d.Class, Perms: perms}
		reason := dangerReason(rule)
		// Self-modification of read-only program files: a write/create/unlink
		// to the app's OWN content_t or exec_t defeats the read-only intent of
		// GenerateTE (a persistence primitive) and must go to review rather
		// than auto-apply (review finding).
		if reason == "" && own[d.TargetType] &&
			(strings.HasSuffix(d.TargetType, "_content_t") || strings.HasSuffix(d.TargetType, "_exec_t")) &&
			!allReadOnly(perms) {
			reason = "self-modification of read-only program files: " + d.TargetType
		}
		// Execution from a WRITABLE owned type (var_lib/log/runtime/tmp/cache) is a
		// W^X violation — a domain that can both write and execute its data dir has
		// a code-injection primitive. The self-modification check above covers the
		// content/exec types; this covers the writable DATA types, which are neither
		// foreign nor _content_t/_exec_t and would otherwise auto-apply (review
		// finding).
		if reason == "" && own[d.TargetType] && isWritableOwnedType(d.TargetType) &&
			(hasPerm(perms, "execute") || hasPerm(perms, "execute_no_trans")) {
			reason = "execution from a writable app type (W^X violation): " + d.TargetType
		}
		// Foreign-type access defaults to review. A type that is neither ours
		// nor on the curated safe allowlist is an unknown grant — it must not
		// fail open the way the finite blocklists did (a read of ssh_home_t
		// would otherwise just become policy). This INCLUDES foreign *_port_t
		// types: the app's OWN port type is in `own` and stays unflagged, but a
		// bind of a foreign port (ssh_port_t, unreserved_port_t) is a broad grant
		// that must be reviewed, not auto-accepted (review finding — the blanket
		// _port_t skip let those through). (review finding)
		if reason == "" && !own[d.TargetType] && !isCapabilityClass(d.Class) &&
			!(safeForeignTypes[d.TargetType] && routineForeignAccess(d.TargetType, perms)) {
			reason = "foreign type access requiring review: " + d.TargetType
		}
		if reason != "" {
			res.Flags = append(res.Flags, Flag{Reason: reason, Rule: rule})
		}
		res.AllowRules = append(res.AllowRules, rule)
	}
	// Flags may reference rules that shouldn't ship silently; flagged rules are
	// still returned so the caller can decide, but Flags is never empty for them.
	res.AllowRules = dropFlagged(res.AllowRules, res.Flags)
	return res
}

// dropFlagged removes flagged rules from the auto-apply set; they ship only
// after human review (the caller can re-add them explicitly).
func dropFlagged(rules []AllowRule, flags []Flag) []AllowRule {
	flagged := map[string]bool{}
	for _, f := range flags {
		flagged[f.Rule.Render()] = true
	}
	var out []AllowRule
	for _, r := range rules {
		if !flagged[r.Render()] {
			out = append(out, r)
		}
	}
	return out
}

func dangerReason(r AllowRule) string {
	if isCapabilityClass(r.Class) {
		for _, p := range r.Perms {
			if !safeCapabilities[p] {
				return "capability requiring review: " + p
			}
		}
	}
	if r.Class == "process" || r.Class == "process2" {
		for _, p := range r.Perms {
			if !safeProcessPerms[p] {
				return "process permission requiring review: " + p
			}
		}
	}
	// Powerful kernel object classes — BPF program/map ops, perf_event, io_uring —
	// grant capabilities far beyond file access and are classic privilege-
	// escalation / sandbox-escape surfaces. The foreign-type gate never sees an
	// OWNED self-target (a widget_t:widget_t:bpf prog_load denial), and the checks
	// above only inspect capability/process classes, so such a rule auto-applied
	// unreviewed. Flag ANY access to these classes regardless of target; a daemon
	// that genuinely needs it gets a reviewed, explicitly-accepted rule (review
	// finding).
	if dangerousClasses[r.Class] {
		return "privileged object class requiring review: " + r.Class
	}
	// FAIL-CLOSED for a domain acting on ITSELF: the base template pre-grants the
	// common self classes, so a self-target rule for anything NOT on the benign
	// allowlist (and not a capability/process class, handled above) is an unusual
	// self-permission — e.g. memprotect:mmap_zero, an exotic socket — that the
	// foreign-type gate never sees (target is owned). Default it to review instead
	// of auto-applying (review finding).
	if r.Source == r.Target && !safeSelfTargetClasses[r.Class] &&
		!isCapabilityClass(r.Class) && r.Class != "process" && r.Class != "process2" {
		return "unrecognized self-target class requiring review: " + r.Class
	}
	if genericTargets[r.Target] {
		return "broad shared type (grants access to other applications' files): " + r.Target
	}
	if dangerousTargets[r.Target] {
		for _, p := range r.Perms {
			if p != "getattr" && p != "search" && p != "read" || r.Target == "shadow_t" || r.Target == "security_t" {
				return "sensitive target type: " + r.Target
			}
		}
	}
	return ""
}

// hasWriteExec reports whether perms grant BOTH a content-modifying permission
// and an execute permission — the write-xor-execute invariant violated, i.e. a
// code-injection primitive. execute/execute_no_trans are the X; anything that is
// not a read-only permission (and readOnlyPerms already classes the execute
// perms as read-only, so they can't count as W) is the W.
func hasWriteExec(perms []string) bool {
	exec, write := false, false
	for _, p := range perms {
		switch {
		case p == "execute" || p == "execute_no_trans":
			exec = true
		case !readOnlyPerms[p]:
			write = true
		}
	}
	return exec && write
}

// FlagWriteExecRules scans a fully ACCUMULATED rule set for owned file types that
// hold both write and execute. It is the cumulative counterpart to the per-denial
// self-modification and writable-type checks in Refine, which see one round at a
// time and are keyed to specific suffixes (_content_t/_exec_t and the writable
// data suffixes). Those miss two things this catches: a hybrid owned type like
// _conf_t (executable, app-writable configuration) that matches no suffix bucket,
// and a write granted in one refinement round with an execute granted in another
// — each round auto-applying an innocuous half while the union is a W^X violation.
// A returned flag fails the verdict closed unless explicitly accepted. (review finding)
func FlagWriteExecRules(p *profile.Profile, rules []AllowRule) []Flag {
	own := ownTypes(p)
	var flags []Flag
	for _, r := range rules {
		if own[r.Target] && isFileClass(r.Class) && hasWriteExec(r.Perms) {
			flags = append(flags, Flag{
				Reason: "cumulative write+execute on an owned type (W^X violation): " + r.Target,
				Rule:   r,
			})
		}
	}
	return flags
}

// isLauncherDomain covers the systemd/init domains that perform the
// exec-time domain transition for a service unit.
func isLauncherDomain(t string) bool {
	switch t {
	case "init_t", "initrc_t", "systemd_generator_t":
		return true
	}
	return false
}

func hasPerm(perms []string, want string) bool {
	for _, p := range perms {
		if p == want {
			return true
		}
	}
	return false
}

// entrypointName prefers the full path when the kernel reported one.
func entrypointName(d avc.Denial) string {
	if d.Path != "" {
		return d.Path
	}
	return d.Name
}

func isFileClass(c string) bool {
	switch c {
	case "file", "dir", "lnk_file", "sock_file", "fifo_file", "chr_file", "blk_file":
		return true
	}
	return false
}

type fcMatcher struct {
	re  *regexp.Regexp
	typ string
}

func compileFCMatchers(p *profile.Profile) []fcMatcher {
	var ms []fcMatcher
	// Exact executable matchers FIRST: an executable path also matches the
	// app's broad content/tree claim, and expectedType returns the first
	// match. Checking exact matchers first keeps a correctly-labeled _exec_t
	// helper from being misread as relabel drift (review finding).
	for _, exe := range p.Executables {
		re, err := regexp.Compile("^" + regexp.QuoteMeta(exe) + "$")
		if err != nil {
			continue
		}
		ms = append(ms, fcMatcher{re, TypeForKind(p.Name, KindExec)})
	}
	for _, pa := range p.Paths {
		re, err := regexp.Compile("^" + pa.Path + "$")
		if err != nil {
			continue
		}
		ms = append(ms, fcMatcher{re, TypeForKind(p.Name, KindFromString(pa.Kind))})
	}
	return ms
}

// readOnlyPerms are non-mutating file/dir/socket permissions. A safe foreign
// type is bypassed only when EVERY requested permission is read-only; any
// write/create/unlink/append/setattr forces review even for an allowlisted
// type (a write to cert_t is not "routine read access").
var readOnlyPerms = map[string]bool{
	"read": true, "open": true, "getattr": true, "lock": true, "ioctl": true,
	"map": true, "search": true, "execute": true, "execute_no_trans": true,
	"list_dir_perms": true, "use": true, "getopt": true, "connectto": true,
}

func allReadOnly(perms []string) bool {
	for _, p := range perms {
		if !readOnlyPerms[p] {
			return false
		}
	}
	return len(perms) > 0
}

func isExecPerm(p string) bool { return p == "execute" || p == "execute_no_trans" }

// routineForeignAccess reports whether every requested permission on a safe
// foreign type is routine enough to auto-apply without review. Read-only perms
// always qualify. execute qualifies ONLY for an *_exec_t target — a binary the
// distro means to be run (hostname_exec_t, ldconfig_exec_t). Executing a
// foreign DATA type (cert_t) is never routine: allReadOnly counted execute as
// read-only, so a cert_t:file execute auto-applied foreign-content execution
// past review (review finding). This is stricter than allReadOnly on purpose —
// allReadOnly still treats execute as non-mutating for the own-file
// self-modification check, where executing your own entrypoint is expected.
func routineForeignAccess(targetType string, perms []string) bool {
	if len(perms) == 0 {
		return false
	}
	execOK := strings.HasSuffix(targetType, "_exec_t")
	for _, p := range perms {
		switch {
		case isExecPerm(p):
			if !execOK {
				return false
			}
		case !readOnlyPerms[p]:
			return false
		}
	}
	return true
}

// isCapabilityClass covers the SELinux capability object classes, including
// the user-namespace variants a confined domain can also exercise.
func isCapabilityClass(c string) bool {
	switch c {
	case "capability", "capability2", "cap_userns", "cap2_userns":
		return true
	}
	return false
}

func expectedType(ms []fcMatcher, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	for _, m := range ms {
		if m.re.MatchString(path) {
			return m.typ, true
		}
	}
	return "", false
}

// RenderRules renders a rule list as .te lines.
func RenderRules(rules []AllowRule) string {
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(r.Render())
		b.WriteString("\n")
	}
	return b.String()
}

// FlagDeclaredCapabilities routes manifest-declared capabilities through the
// same danger gate as observed ones. Declared privilege must not bypass the
// human review that an observed denial for the same capability would get.
func FlagDeclaredCapabilities(app string, caps []string) []Flag {
	dom := DomainType(app)
	var flags []Flag
	for _, c := range caps {
		// Emit each declared capability under its CORRECT class — bpf/perfmon/
		// checkpoint_restore/... are capability2, so a hard-coded `capability`
		// class produced an invalid review artifact that, if accepted, generated an
		// uncompilable module (review finding — matches GenerateTE's partitioning).
		class := "capability"
		if capability2Perms[c] {
			class = "capability2"
		}
		rule := AllowRule{Source: dom, Target: dom, Class: class, Perms: []string{c}}
		if reason := dangerReason(rule); reason != "" {
			flags = append(flags, Flag{Reason: reason + " (declared in manifest)", Rule: rule})
		}
	}
	return flags
}
