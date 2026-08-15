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

// safeForeignTypes is the curated allowlist of distro types a confined daemon
// routinely reads with no meaningful risk. Everything else foreign goes to
// review by default — the set of dangerous types is open-ended, so an
// allowlist is the only fail-closed posture.
var safeForeignTypes = map[string]bool{
	"cert_t":            true, // TLS certs and keys under /etc/pki
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

// dangerousProcessPerms are high-impact permissions on the process class:
// executable memory (defeats W^X), stack/heap exec, and ptrace. They are not
// capability-class, so the capability-only check missed them.
var dangerousProcessPerms = map[string]bool{
	"execmem": true, "execstack": true, "execheap": true, "ptrace": true,
}

var dangerousTargets = map[string]bool{
	"shadow_t": true, "etc_t": true, "security_t": true, "kernel_t": true,
	"init_t": true, "memory_device_t": true, "fixed_disk_device_t": true,
	"selinux_config_t": true, "auth_cache_t": true, "sysctl_t": true,
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
		remaining = append(remaining, d)
	}
	for _, d := range avc.Merge(remaining) {
		if d.SourceType != dom {
			// A foreign domain denied execute on one of our types means we
			// labeled an entrypoint as content — fatal, and invisible if we
			// only ever look at denials sourced from our own domain.
			if own[d.TargetType] && isFileClass(d.Class) && hasPerm(d.Perms, "execute") {
				res.Entrypoints = append(res.Entrypoints, EntrypointIssue{
					Name: entrypointName(d), SourceType: d.SourceType, ObservedType: d.TargetType,
				})
			}
			continue // other domains' business is not ours
		}
		perms := d.Perms
		// Executing a helper requires the whole read+exec set; granting only
		// the observed perm makes each verification run surface one more
		// (getattr → read → open → map), costing a round per permission.
		if d.Class == "file" && strings.HasSuffix(d.TargetType, "_exec_t") && hasPerm(perms, "execute") {
			perms = []string{"execute", "execute_no_trans", "getattr", "map", "open", "read"}
		}
		rule := AllowRule{Source: dom, Target: d.TargetType, Class: d.Class, Perms: perms}
		reason := dangerReason(rule)
		// Foreign-type access defaults to review. A type that is neither ours,
		// a port type, nor on the curated safe allowlist is an unknown grant —
		// it must not fail open the way the finite blocklists did (a read of
		// ssh_home_t would otherwise just become policy). (review finding)
		if reason == "" && !own[d.TargetType] && !isCapabilityClass(d.Class) &&
			!strings.HasSuffix(d.TargetType, "_port_t") &&
			!(safeForeignTypes[d.TargetType] && allReadOnly(perms)) {
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
			if dangerousProcessPerms[p] {
				return "high-impact process permission: " + p
			}
		}
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
		rule := AllowRule{Source: dom, Target: dom, Class: "capability", Perms: []string{c}}
		if reason := dangerReason(rule); reason != "" {
			flags = append(flags, Flag{Reason: reason + " (declared in manifest)", Rule: rule})
		}
	}
	return flags
}
