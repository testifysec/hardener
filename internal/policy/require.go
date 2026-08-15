package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/testifysec/hardener/internal/profile"
)

// IsOwnType reports whether t is one of the types the module declares for
// this profile (its domain, exec, port, and file types).
func IsOwnType(p *profile.Profile, t string) bool {
	return ownTypes(p)[t]
}

// ownTypes returns every type the module itself declares for this profile.
func ownTypes(p *profile.Profile) map[string]bool {
	app := SafeName(p.Name)
	own := map[string]bool{
		DomainType(p.Name): true,
		app + "_exec_t":    true,
		PortType(p.Name):   true,
	}
	for _, k := range []Kind{KindConf, KindVarLib, KindLog, KindRuntime, KindContent, KindTmp, KindCache, KindUnit} {
		own[TypeForKind(p.Name, k)] = true
	}
	return own
}

// RenderRefinedSection renders refinement allow rules with the gen_require
// block for any foreign types they reference.
func RenderRefinedSection(p *profile.Profile, rules []AllowRule) string {
	if len(rules) == 0 {
		return ""
	}
	own := ownTypes(p)
	foreign := map[string]bool{}
	for _, r := range rules {
		if !own[r.Target] && r.Target != "self" {
			foreign[r.Target] = true
		}
	}
	var b strings.Builder
	b.WriteString("\n########################################\n# Observed refinements\n########################################\n")
	if len(foreign) > 0 {
		names := make([]string, 0, len(foreign))
		for t := range foreign {
			names = append(names, t)
		}
		sort.Strings(names)
		b.WriteString("gen_require(`\n")
		for _, t := range names {
			fmt.Fprintf(&b, "\ttype %s;\n", t)
		}
		b.WriteString("')\n")
	}
	sorted := append([]AllowRule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Render() < sorted[j].Render() })
	for _, r := range sorted {
		b.WriteString(r.Render())
		b.WriteString("\n")
	}
	return b.String()
}
