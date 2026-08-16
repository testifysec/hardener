// Package conformance verifies observed application behavior against a
// claimed privilege set. The same comparison serves two supply-chain party
// classes with different sourcing and stakes:
//
//   - second party: the claim is the supplier's declared privilege manifest,
//     delivered with the artifact. Observed-but-undeclared behavior is a
//     supplier finding (noncompliance or compromise), not something to grant.
//   - first party: the claim is a baseline committed in the application's own
//     repo — a privilege lockfile. Observed-but-unbaselined behavior is drift,
//     and accepting it is an explicit, reviewed baseline update.
//
// Third-party artifacts have no counterparty to hold to a claim, so any
// comparison there is advisory.
package conformance

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
)

// foreignKey identifies one foreign access at type:class:permission granularity,
// so read/write/execute on the same type are distinct entries in the
// declaration comparison (review finding — type-only normalization let a
// declared read silently cover a new write/execute).
func foreignKey(target, class, perm string) string {
	return target + ":" + class + ":" + perm
}

// Observed is the normalized behavior summary extracted from a verified run.
type Observed struct {
	Capabilities     []string       `yaml:"capabilities,omitempty"`
	Ports            []profile.Port `yaml:"ports,omitempty"`
	ForeignTypes     []string       `yaml:"foreign_types,omitempty"`
	ForeignPortBinds []string       `yaml:"foreign_port_binds,omitempty"`
	// BaseGrants is the base template's unconditional privilege set; included
	// so undeclared use of shell exec / etc read cannot slip the contract.
	BaseGrants []string `yaml:"base_grants,omitempty"`
}

// Finding is one observed behavior absent from the declaration.
type Finding struct {
	Kind     string // capability | port | port-bind | foreign-type
	Item     string
	Severity string // high | medium
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] undeclared %s: %s", f.Severity, f.Kind, f.Item)
}

// Report is the outcome of comparing observed behavior to a declaration.
type Report struct {
	Undeclared  []Finding // observed but not declared — the violation/drift signal
	Unexercised []string  // declared but not observed — coverage or over-declaration
}

// ExtractObserved distills the profile and the final refined rules into the
// comparable behavior summary.
func ExtractObserved(p *profile.Profile, rules []policy.AllowRule) Observed {
	dom := policy.DomainType(p.Name)
	obs := Observed{Ports: append([]profile.Port(nil), p.Ports...)}
	capSet, foreignSet, bindSet := map[string]bool{}, map[string]bool{}, map[string]bool{}
	// Manifest-declared capabilities are granted in the base TE, so they are
	// observed behavior for conformance purposes — otherwise a declared
	// dac_override would vanish from supplier/baseline comparison.
	for _, c := range p.Capabilities {
		capSet[c] = true
	}
	for _, r := range rules {
		switch {
		case (r.Class == "capability" || r.Class == "capability2") && (r.Target == dom || r.Target == "self"):
			for _, perm := range r.Perms {
				capSet[perm] = true
			}
		case policy.IsOwnType(p, r.Target):
			// access to the app's own types is the point of the policy
		case strings.HasSuffix(r.Target, "_port_t"):
			// name_bind is the inbound-listener signal compared against
			// ForeignPortBinds. Any OTHER port permission (name_connect for
			// outbound, recv/send) must NOT be silently dropped: previously
			// only name_bind was recorded, so a name_connect on http_port_t
			// vanished from both ForeignPortBinds and ForeignTypes and passed
			// second-party conformance as undeclared outbound access (review
			// finding). Surface any non-bind port access as a foreign type so
			// it still faces the declaration comparison.
			for _, perm := range r.Perms {
				if perm == "name_bind" {
					// Key the bind by type:class so a tcp_socket bind and a
					// udp_socket bind on the SAME *_port_t are distinct entries.
					// Keying by type alone let an added UDP bind collapse into an
					// existing TCP one, so first-party drift and second-party
					// undeclared behavior passed on identical baselines (review
					// finding).
					bindSet[r.Target+":"+r.Class] = true
				} else {
					foreignSet[foreignKey(r.Target, r.Class, perm)] = true
				}
			}
		default:
			// Key foreign access by type:class:PERMISSION, not type alone — a
			// declared READ of cert_t must not silently permit a new WRITE or
			// EXECUTE to cert_t, which type-only normalization let pass as
			// identical (review finding). Per-permission granularity also keeps
			// "used less than declared" from becoming a false finding.
			for _, perm := range r.Perms {
				foreignSet[foreignKey(r.Target, r.Class, perm)] = true
			}
		}
	}
	obs.Capabilities = sortedKeys(capSet)
	obs.ForeignTypes = sortedKeys(foreignSet)
	obs.ForeignPortBinds = sortedKeys(bindSet)
	obs.BaseGrants = append([]string(nil), policy.BaseInterfaces...)
	return obs
}

// Compare checks observed behavior against a declaration in both directions.
func Compare(decl *profile.Declaration, obs Observed) Report {
	rep := Report{}
	declCaps := toSet(decl.Capabilities)
	declTypes := toSet(decl.ForeignTypes)
	declBinds := toSet(decl.ForeignPortBinds)
	declPorts := map[string]bool{}
	for _, po := range decl.Ports {
		declPorts[portKey(po)] = true
	}

	for _, c := range obs.Capabilities {
		if !declCaps[c] {
			rep.Undeclared = append(rep.Undeclared, Finding{Kind: "capability", Item: c, Severity: "high"})
		}
	}
	for _, po := range obs.Ports {
		if !declPorts[portKey(po)] {
			rep.Undeclared = append(rep.Undeclared, Finding{Kind: "port", Item: portKey(po), Severity: "high"})
		}
	}
	for _, b := range obs.ForeignPortBinds {
		if !declBinds[b] {
			rep.Undeclared = append(rep.Undeclared, Finding{Kind: "port-bind", Item: b, Severity: "high"})
		}
	}
	for _, ft := range obs.ForeignTypes {
		if !declTypes[ft] {
			rep.Undeclared = append(rep.Undeclared, Finding{Kind: "foreign-type", Item: ft, Severity: "medium"})
		}
	}
	declBase := toSet(decl.BaseGrants)
	for _, g := range obs.BaseGrants {
		if !declBase[g] {
			rep.Undeclared = append(rep.Undeclared, Finding{Kind: "base-grant", Item: g, Severity: "medium"})
		}
	}

	obsCaps := toSet(obs.Capabilities)
	obsTypes := toSet(obs.ForeignTypes)
	obsBinds := toSet(obs.ForeignPortBinds)
	obsPorts := map[string]bool{}
	for _, po := range obs.Ports {
		obsPorts[portKey(po)] = true
	}
	for _, c := range decl.Capabilities {
		if !obsCaps[c] {
			rep.Unexercised = append(rep.Unexercised, "capability "+c)
		}
	}
	for _, po := range decl.Ports {
		if !obsPorts[portKey(po)] {
			rep.Unexercised = append(rep.Unexercised, "port "+portKey(po))
		}
	}
	for _, b := range decl.ForeignPortBinds {
		if !obsBinds[b] {
			rep.Unexercised = append(rep.Unexercised, "port-bind "+b)
		}
	}
	for _, ft := range decl.ForeignTypes {
		if !obsTypes[ft] {
			rep.Unexercised = append(rep.Unexercised, "foreign type "+ft)
		}
	}
	return rep
}

// Verdict maps a conformance report to pass/fail per party class.
func Verdict(party string, rep Report) (fatal bool, reason string) {
	if len(rep.Undeclared) == 0 {
		return false, ""
	}
	items := make([]string, 0, len(rep.Undeclared))
	for _, f := range rep.Undeclared {
		items = append(items, f.Kind+" "+f.Item)
	}
	list := strings.Join(items, ", ")
	switch party {
	case "second":
		return true, "observed behavior the supplier never declared: " + list
	case "first":
		return true, "privilege drift from committed baseline: " + list + " (review, then --update-baseline to accept)"
	default: // third party: no counterparty holds a claim; advisory only
		return false, ""
	}
}

// SaveBaseline writes an observed behavior summary as a first-party baseline.
func SaveBaseline(path string, obs Observed) error {
	raw, err := yaml.Marshal(profile.Declaration{
		Capabilities:     obs.Capabilities,
		Ports:            obs.Ports,
		ForeignTypes:     obs.ForeignTypes,
		ForeignPortBinds: obs.ForeignPortBinds,
		BaseGrants:       obs.BaseGrants,
	})
	if err != nil {
		return err
	}
	_ = obs // BaseGrants persisted via the Declaration marshal below
	header := "# hardener privilege baseline — the app's accepted least-privilege envelope.\n" +
		"# Regenerate deliberately with --update-baseline after reviewing any drift.\n"
	return os.WriteFile(path, append([]byte(header), raw...), 0o644)
}

// LoadDeclaration reads a declaration/baseline file.
func LoadDeclaration(path string) (*profile.Declaration, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d profile.Declaration
	if err := yaml.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &d, nil
}

func toSet(items []string) map[string]bool {
	m := map[string]bool{}
	for _, it := range items {
		m[it] = true
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func portKey(p profile.Port) string { return fmt.Sprintf("%s/%d", p.Proto, p.Port) }
