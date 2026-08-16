// Package policy synthesizes SELinux policy (.te/.fc) from a security profile
// and refines it from observed AVC denials.
package policy

import (
	"regexp"
	"strings"
)

// Kind is the semantic class of a filesystem path.
type Kind int

const (
	KindExec Kind = iota
	KindConf
	KindVarLib
	KindLog
	KindRuntime
	KindContent
	KindTmp
	KindCache
	KindUnit
)

func (k Kind) String() string {
	switch k {
	case KindExec:
		return "exec"
	case KindConf:
		return "conf"
	case KindVarLib:
		return "var_lib"
	case KindLog:
		return "log"
	case KindRuntime:
		return "runtime"
	case KindContent:
		return "content"
	case KindTmp:
		return "tmp"
	case KindCache:
		return "cache"
	case KindUnit:
		return "unit"
	}
	return "unknown"
}

// KindFromString is the inverse of Kind.String for profile YAML round-trips.
func KindFromString(s string) Kind {
	for _, k := range []Kind{KindExec, KindConf, KindVarLib, KindLog, KindRuntime, KindContent, KindTmp, KindCache, KindUnit} {
		if k.String() == s {
			return k
		}
	}
	return KindContent
}

// KnownKind reports whether s names a valid path kind. Manifest load must
// reject anything else instead of letting KindFromString silently fall back to
// KindContent: content paths receive can_exec, so a typo like "confg" would
// quietly make a configuration or state file executable (review finding).
func KnownKind(s string) bool {
	for _, k := range []Kind{KindExec, KindConf, KindVarLib, KindLog, KindRuntime, KindContent, KindTmp, KindCache, KindUnit} {
		if k.String() == s {
			return true
		}
	}
	return false
}

// ClassifyPath maps a path to its semantic kind. exec marks ELF/script entrypoints.
func ClassifyPath(path string, exec bool) Kind {
	switch {
	case strings.Contains(path, "/systemd/system/"):
		return KindUnit
	case exec:
		return KindExec
	case strings.HasPrefix(path, "/etc/"), path == "/etc", isEtcDir(path):
		return KindConf
	case strings.HasPrefix(path, "/var/lib/"):
		return KindVarLib
	case strings.HasPrefix(path, "/var/log/"):
		return KindLog
	case strings.HasPrefix(path, "/run/"), strings.HasPrefix(path, "/var/run/"):
		return KindRuntime
	case strings.HasPrefix(path, "/tmp/"), strings.HasPrefix(path, "/var/tmp/"):
		return KindTmp
	case strings.HasPrefix(path, "/var/cache/"):
		return KindCache
	default:
		return KindContent
	}
}

func isEtcDir(path string) bool {
	return strings.HasPrefix(path, "/etc") && !strings.Contains(strings.TrimPrefix(path, "/etc"), "/")
}

// TypeForKind returns the SELinux type name for an app's path kind.
func TypeForKind(app string, k Kind) string {
	app = SafeName(app)
	switch k {
	case KindExec:
		return app + "_exec_t"
	case KindConf:
		return app + "_conf_t"
	case KindVarLib:
		return app + "_var_lib_t"
	case KindLog:
		return app + "_log_t"
	case KindRuntime:
		return app + "_runtime_t"
	case KindTmp:
		return app + "_tmp_t"
	case KindCache:
		return app + "_cache_t"
	case KindUnit:
		// systemd unit files take the shared base type, not an app-specific
		// one: systemd itself must read the unit to start the service, and the
		// module never declares an app unit type — emitting app_unit_file_t
		// produced an fc entry referencing an undeclared type and an
		// uncompilable module (review finding).
		return "systemd_unit_file_t"
	default:
		return app + "_content_t"
	}
}

// DomainType returns the process domain for an app.
func DomainType(app string) string { return SafeName(app) + "_t" }

// PortType returns the port type for an app.
func PortType(app string) string { return SafeName(app) + "_port_t" }

var unsafeChars = regexp.MustCompile(`[^a-z0-9_]+`)

// SafeName converts an arbitrary app name into a valid SELinux identifier.
func SafeName(name string) string {
	s := strings.ToLower(name)
	s = unsafeChars.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		s = "app"
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "app_" + s
	}
	return s
}
