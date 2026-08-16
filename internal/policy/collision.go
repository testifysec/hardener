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
	claimed := map[string]string{}
	for _, line := range strings.Split(baseFileContexts, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		claimed[fields[0]] = contextType(fields[len(fields)-1])
	}
	var out []Collision
	// matchKey is the fc path spec as GenerateFC emits it (that is what semodule
	// dedups on and what appears in the base file_contexts). recordPath is the
	// raw manifest path, kept for exclusion (GenerateFCExcluding filters on the
	// raw p.Paths / p.Executables values).
	check := func(matchKey, recordPath, want string) {
		base, ok := claimed[matchKey]
		if !ok || base == want {
			// Not claimed, or a previous install of this same module.
			// Re-declaring an identical spec is idempotent; treating it as a
			// conflict would drop our own labels and quietly leave the
			// application unconfined on re-runs.
			return
		}
		out = append(out, Collision{Path: recordPath, BaseType: base, WouldBeType: want})
	}
	// GenerateFC emits path claims verbatim, so match on the raw path.
	for _, pa := range p.Paths {
		check(pa.Path, pa.Path, TypeForKind(p.Name, KindFromString(pa.Kind)))
	}
	// GenerateFC emits an _exec_t line for every executable and ESCAPES it
	// (escapeFCPath: spaces → \s, regex metacharacters quoted). The base claim
	// to match is therefore the escaped form — comparing the raw path missed a
	// collision like "Plex\sMedia\sServer", leaving a duplicate spec that makes
	// semodule reject the module (review finding). Match on the escaped form,
	// record the raw path for exclusion.
	for _, exe := range p.Executables {
		check(escapeFCPath(exe), exe, TypeForKind(p.Name, KindExec))
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
	// Executables collide too (GenerateFC emits an _exec_t line per executable),
	// so a colliding executable must be dropped from the fc as well — otherwise
	// GenerateFC re-emits the duplicate spec we set out to exclude (review
	// finding).
	trimmed.Executables = nil
	for _, exe := range p.Executables {
		if !skip[exe] {
			trimmed.Executables = append(trimmed.Executables, exe)
		}
	}
	return GenerateFC(&trimmed)
}

func contextType(ctx string) string {
	parts := strings.Split(ctx, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ctx
}
