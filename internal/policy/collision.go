package policy

import (
	"fmt"
	"strings"

	"github.com/testifysec/hardener/internal/profile"
)

// Collision is a path expression the distro base policy already claims.
// Re-declaring it makes semodule reject the whole module, so the generated
// module must defer — and the operator must be told, because the application's
// files will keep a label we did not choose.
type Collision struct {
	Path        string
	BaseType    string
	WouldBeType string
}

// Render describes the collision for the report.
func (c Collision) Render() string {
	return fmt.Sprintf("%s already claimed by base policy as %s (wanted %s)", c.Path, c.BaseType, c.WouldBeType)
}

// FindCollisions compares a profile's path claims against the contents of the
// system file_contexts, matching on the exact path expression — that is the
// key semodule treats as a duplicate.
func FindCollisions(p *profile.Profile, baseFileContexts string) []Collision {
	// A file_contexts entry is `regex [selector] context`. The SELECTOR (`--`
	// regular file, `-d` dir, `-l` symlink, ...) is part of the identity: SELinux
	// permits IDENTICAL regexes with DIFFERENT selectors, so keying only on the
	// regex overwrote one entry with another — missing a real collision or
	// reporting a false one depending on record order (review finding). Keep every
	// (selector, type) per regex and compare selectors for overlap.
	type baseEntry struct{ sel, typ string }
	claimed := map[string][]baseEntry{}
	for _, line := range strings.Split(baseFileContexts, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sel := ""
		if len(fields) >= 3 {
			sel = fields[1] // -- / -d / -l / -c / -b / -s / -p
		}
		claimed[fields[0]] = append(claimed[fields[0]], baseEntry{sel: sel, typ: contextType(fields[len(fields)-1])})
	}
	// A selector-less entry (empty) matches EVERY file type, so it overlaps any
	// selector; two DIFFERENT specific selectors (-- vs -d) never overlap.
	selOverlap := func(a, b string) bool { return a == "" || b == "" || a == b }
	var out []Collision
	// matchKey is the fc path spec as GenerateFC emits it (what semodule dedups on
	// and what appears in the base file_contexts); ourSel is the selector our .fc
	// uses for this claim; recordPath is the raw manifest path, kept for exclusion.
	check := func(matchKey, ourSel, recordPath, want string) {
		for _, e := range claimed[matchKey] {
			if !selOverlap(e.sel, ourSel) || e.typ == want {
				// Different file type (no overlap), or a previous install of this
				// same module (idempotent — re-declaring our own type is not a
				// conflict). Keep scanning; another overlapping entry may collide.
				continue
			}
			out = append(out, Collision{Path: recordPath, BaseType: e.typ, WouldBeType: want})
			return
		}
	}
	// GenerateFC emits PATH claims with NO selector (matches all file types), so
	// they overlap any base selector; match on the raw path.
	for _, pa := range p.Paths {
		check(pa.Path, "", pa.Path, TypeForKind(p.Name, KindFromString(pa.Kind)))
	}
	// GenerateFC emits each EXECUTABLE with the `--` selector and ESCAPES the path
	// (escapeFCPath: spaces → \s, regex metacharacters quoted). Match on the
	// escaped form with the `--` selector, record the raw path for exclusion.
	for _, exe := range p.Executables {
		check(escapeFCPath(exe), "--", exe, TypeForKind(p.Name, KindExec))
	}
	return out
}

// GenerateFCExcluding renders file contexts omitting colliding path claims.
func GenerateFCExcluding(p *profile.Profile, cols []Collision) string {
	if len(cols) == 0 {
		return GenerateFC(p)
	}
	skip := map[string]bool{}
	for _, c := range cols {
		skip[c.Path] = true
	}
	trimmed := *p
	trimmed.Paths = nil
	for _, pa := range p.Paths {
		if !skip[pa.Path] {
			trimmed.Paths = append(trimmed.Paths, pa)
		}
	}
	// Only data/config PATHS are excluded here. An EXECUTABLE collision is NOT
	// silently excluded: dropping the entrypoint's _exec_t line would leave the
	// domain transition impossible and the service unconfined, so the pipeline
	// treats an executable collision as fatal instead (see pipeline.observe).
	// GenerateFCExcluding therefore never legitimately excludes an executable.
	return GenerateFC(&trimmed)
}

func contextType(ctx string) string {
	parts := strings.Split(ctx, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ctx
}
