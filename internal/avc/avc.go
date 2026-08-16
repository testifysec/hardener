// Package avc parses SELinux AVC denial records from ausearch/audit.log output.
package avc

import (
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Denial is one parsed AVC record.
type Denial struct {
	Perms      []string // sorted, e.g. ["open", "read"]
	Comm       string
	Name       string // basename, when the kernel reports name=
	Path       string // full path, when the kernel reports path=
	SourceType string // type portion of scontext
	TargetType string // type portion of tcontext
	Class      string // file, dir, tcp_socket, capability, ...
	Src        int    // source port for name_bind denials
	Ino        string // target inode (used to correlate the sibling PATH record)
	Permissive bool
}

var (
	avcRe   = regexp.MustCompile(`avc:\s+denied\s+\{([^}]*)\}\s+for\s+(.*)$`)
	fieldRe = regexp.MustCompile(`(\w+)=("[^"]*"|\S+)`)
	eventRe = regexp.MustCompile(`msg=audit\(([0-9.:]+)\)`)
)

// ParseLogWithPaths parses AVC denials and correlates full paths from
// sibling type=PATH records sharing the same audit event ID. Kernel AVCs
// frequently report only name= (a basename); without the full path the
// refine stage cannot distinguish a mislabeled file (fix: restorecon) from a
// genuine missing permission (fix: allow rule) and over-grants type-wide.
func ParseLogWithPaths(log string) []Denial {
	type indexed struct {
		d     Denial
		event string
	}
	var ds []indexed
	// event id → inode → PATH name, plus a per-event fallback used only when
	// exactly one PATH record exists (so a single-item event still correlates
	// even if the AVC reported no inode).
	byInode := map[string]map[string]string{}
	loneName := map[string]string{}
	loneCount := map[string]int{}
	for _, line := range strings.Split(log, "\n") {
		ev := ""
		if m := eventRe.FindStringSubmatch(line); m != nil {
			ev = m[1]
		}
		if strings.Contains(line, "type=PATH") && ev != "" {
			var name, inode string
			for _, f := range fieldRe.FindAllStringSubmatch(line, -1) {
				switch f[1] {
				case "name":
					name = strings.Trim(f[2], `"`)
				case "inode":
					inode = strings.Trim(f[2], `"`)
				}
			}
			if name == "" {
				continue
			}
			if byInode[ev] == nil {
				byInode[ev] = map[string]string{}
			}
			if inode != "" {
				byInode[ev][inode] = name
			}
			loneName[ev] = name
			loneCount[ev]++
			continue
		}
		if d, err := ParseLine(line); err == nil {
			ds = append(ds, indexed{*d, ev})
		}
	}
	out := make([]Denial, 0, len(ds))
	for _, x := range ds {
		if x.d.Path == "" && x.event != "" {
			// Prefer an exact inode match; fall back to the sole PATH name
			// only when the event has exactly one. Never guess among several.
			if x.d.Ino != "" && byInode[x.event] != nil {
				if name, ok := byInode[x.event][x.d.Ino]; ok {
					x.d.Path = name
				}
			}
			if x.d.Path == "" && loneCount[x.event] == 1 {
				x.d.Path = loneName[x.event]
			}
		}
		out = append(out, x.d)
	}
	return out
}

// ParseLine parses a single audit record line. Returns an error for non-AVC lines.
func ParseLine(line string) (*Denial, error) {
	if !strings.Contains(line, "type=AVC") && !strings.Contains(line, "avc: ") {
		return nil, errors.New("not an AVC record")
	}
	m := avcRe.FindStringSubmatch(line)
	if m == nil {
		return nil, errors.New("not an AVC denial")
	}
	d := &Denial{Perms: splitSorted(m[1])}
	for _, f := range fieldRe.FindAllStringSubmatch(m[2], -1) {
		key, val := f[1], strings.Trim(f[2], `"`)
		switch key {
		case "comm":
			d.Comm = val
		case "name":
			d.Name = val
		case "path":
			d.Path = val
		case "scontext":
			d.SourceType = contextType(val)
		case "tcontext":
			d.TargetType = contextType(val)
		case "tclass":
			d.Class = val
		case "src":
			d.Src, _ = strconv.Atoi(val)
		case "ino":
			d.Ino = val
		case "permissive":
			d.Permissive = val == "1"
		}
	}
	return d, nil
}

// ParseLog extracts every AVC denial from a blob of ausearch output.
func ParseLog(log string) []Denial {
	var out []Denial
	for _, line := range strings.Split(log, "\n") {
		if d, err := ParseLine(line); err == nil {
			out = append(out, *d)
		}
	}
	return out
}

// Merge collapses denials sharing (source, target, class, PATH, inode) and
// unions their perms. Path and inode are part of the key: two distinct paths
// that happen to share a SELinux type must NOT be folded into one denial — that
// dropped a path and let a per-path classification (a relabel, or which file is
// the mislabeled entrypoint) apply to the wrong file (review finding). Type-wide
// allow rules that lose their path are re-collapsed by (source,target,class)
// downstream (normalizeRules), so nothing over-broadens.
func Merge(ds []Denial) []Denial {
	type key struct{ s, t, c, p, i string }
	idx := map[key]int{}
	var out []Denial
	for _, d := range ds {
		k := key{d.SourceType, d.TargetType, d.Class, d.Path, d.Ino}
		if i, ok := idx[k]; ok {
			out[i].Perms = unionSorted(out[i].Perms, d.Perms)
			continue
		}
		idx[k] = len(out)
		out = append(out, d)
	}
	return out
}

// contextType extracts the type from user:role:type:level.
func contextType(ctx string) string {
	parts := strings.Split(ctx, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ctx
}

func splitSorted(s string) []string {
	perms := strings.Fields(s)
	sort.Strings(perms)
	return perms
}

func unionSorted(a, b []string) []string {
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
