// Package elfscan derives privilege predictions from a binary's dynamic
// symbol imports. Dynamic observation only proves what the exercise touched;
// static imports say what the code *can* do. The difference between the two
// is the coverage gap report — the honest answer to "did we test enough?".
//
// Limits, stated plainly: a statically linked binary (most Go daemons) has no
// dynamic imports, so this yields nothing there — that case needs syscall-site
// disassembly, which is future work. And imports over-approximate: linking
// setuid() does not mean calling it. Predictions are therefore never turned
// into policy, only into questions.
package elfscan

import (
	"regexp"
	"strings"
)

// Prediction is one capability the binary appears to have, with its evidence.
type Prediction struct {
	Feature string // stable feature key, e.g. "port-bind", "cap-setuid"
	Reason  string // human-readable evidence
}

// symbolFeatures maps imported libc symbols to policy-relevant features.
var symbolFeatures = map[string]string{
	"bind":        "port-bind",
	"listen":      "port-bind",
	"accept":      "port-bind",
	"accept4":     "port-bind",
	"connect":     "outbound-connect",
	"getaddrinfo": "dns-resolve",
	"setuid":      "cap-setuid",
	"seteuid":     "cap-setuid",
	"setresuid":   "cap-setuid",
	"setgid":      "cap-setgid",
	"setegid":     "cap-setgid",
	"setresgid":   "cap-setgid",
	"setgroups":   "cap-setgid",
	"initgroups":  "cap-setgid",
	"chown":       "cap-chown",
	"fchown":      "cap-chown",
	"lchown":      "cap-chown",
	"mlock":       "cap-ipc-lock",
	"mlockall":    "cap-ipc-lock",
	"execve":      "exec-other",
	"execvp":      "exec-other",
	"system":      "exec-other",
	"popen":       "exec-other",
	"fork":        "fork",
	"unlink":      "file-unlink",
	"unlinkat":    "file-unlink",
}

// featureMarkers maps a feature to substrings whose presence in the final .te
// indicates the dynamic loop granted (or base rules cover) that behavior.
var featureMarkers = map[string][]string{
	"port-bind":        {"name_bind"},
	"outbound-connect": {"name_connect", "corenet_tcp_connect"},
	"dns-resolve":      {"auth_use_nsswitch", "sysnet_dns_name_resolve"},
	"cap-setuid":       {"capability { setgid setuid }", "capability setuid", "setuid "},
	"cap-setgid":       {"capability { setgid setuid }", "capability setgid", "setgid "},
	"cap-chown":        {"chown"},
	"cap-ipc-lock":     {"ipc_lock"},
	"exec-other":       {"corecmd_exec_bin", "corecmd_exec_shell"},
	"fork":             {"fork"},
	"file-unlink":      {"manage_files_pattern", "unlink"},
}

var undSymRe = regexp.MustCompile(`\bUND\s+(\S+)`)

// ParseDynSyms extracts undefined (imported) symbol names from
// `readelf --dyn-syms -W` output, stripping @GLIBC version suffixes.
func ParseDynSyms(out string) map[string]bool {
	syms := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		m := undSymRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		if i := strings.Index(name, "@"); i > 0 {
			name = name[:i]
		}
		if name != "" {
			syms[name] = true
		}
	}
	return syms
}

// Predict maps imported symbols to deduplicated feature predictions.
func Predict(syms map[string]bool) []Prediction {
	byFeature := map[string][]string{}
	for sym := range syms {
		if f, ok := symbolFeatures[sym]; ok {
			byFeature[f] = append(byFeature[f], sym)
		}
	}
	var out []Prediction
	for f, evidence := range byFeature {
		out = append(out, Prediction{Feature: f, Reason: "imports " + strings.Join(sortStrings(evidence), ", ")})
	}
	return sortPredictions(out)
}

// CoverageGaps returns predictions with no corresponding grant in the final
// policy: behavior the binary is capable of that the exercise never drove.
func CoverageGaps(preds []Prediction, finalTE string) []Prediction {
	var gaps []Prediction
	for _, p := range preds {
		covered := false
		for _, marker := range featureMarkers[p.Feature] {
			if strings.Contains(finalTE, marker) {
				covered = true
				break
			}
		}
		if !covered {
			gaps = append(gaps, p)
		}
	}
	return gaps
}

func sortStrings(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func sortPredictions(ps []Prediction) []Prediction {
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			if ps[j].Feature < ps[i].Feature {
				ps[i], ps[j] = ps[j], ps[i]
			}
		}
	}
	return ps
}
