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
	Permissive bool
}

var (
	avcRe   = regexp.MustCompile(`avc:\s+denied\s+\{([^}]*)\}\s+for\s+(.*)$`)
	fieldRe = regexp.MustCompile(`(\w+)=("[^"]*"|\S+)`)
)

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

// Merge collapses denials sharing (source, target, class) and unions their perms.
func Merge(ds []Denial) []Denial {
	type key struct{ s, t, c string }
	idx := map[key]int{}
	var out []Denial
	for _, d := range ds {
		k := key{d.SourceType, d.TargetType, d.Class}
		if i, ok := idx[k]; ok {
			out[i].Perms = unionSorted(out[i].Perms, d.Perms)
			if out[i].Path == "" {
				out[i].Path = d.Path
			}
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
