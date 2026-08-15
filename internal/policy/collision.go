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
	for _, pa := range p.Paths {
		base, ok := claimed[pa.Path]
		if !ok {
			continue
		}
		want := TypeForKind(p.Name, KindFromString(pa.Kind))
		if base == want {
			// A previous install of this same module. Re-declaring is
			// idempotent; treating it as a conflict would drop our own labels
			// and quietly leave the application unconfined on re-runs.
			continue
		}
		out = append(out, Collision{Path: pa.Path, BaseType: base, WouldBeType: want})
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
	return GenerateFC(&trimmed)
}

func contextType(ctx string) string {
	parts := strings.Split(ctx, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ctx
}
