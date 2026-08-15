package pipeline

import (
	"fmt"
	"strings"
)

// RenderReport renders one target result as markdown.
func RenderReport(res *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — SELinux confinement report\n\n", res.Target.Name)
	fmt.Fprintf(&b, "- License class: %s\n- Source: %s\n- Domain: `%s`\n\n", res.Target.License, res.Target.Source, res.Domain)

	status := "PASS"
	if len(res.AcceptedExceptions) > 0 || (len(res.Flags) > 0 && res.FlagsAccepted) {
		status = "PASS (with accepted exceptions)"
	}
	if res.IsFailure() {
		status = "FAIL"
	}
	fmt.Fprintf(&b, "**Overall: %s**\n\n", status)
	if res.FailureReason != "" {
		fmt.Fprintf(&b, "Failure: %s\n\n", res.FailureReason)
	}

	b.WriteString("## Observation rounds (permissive domain)\n\n| Round | Denials | New rules | Relabels | Exercise |\n|---|---|---|---|---|\n")
	for i, r := range res.Rounds {
		fmt.Fprintf(&b, "| %d | %d | %d | %d | %s |\n", i+1, r.Denials, r.NewRules, r.Relabels, okStr(r.ExerciseOK))
	}

	fmt.Fprintf(&b, "\n## Enforcing verification\n\n")
	fmt.Fprintf(&b, "- Process runs in `%s`: %s\n", res.Domain, okStr(res.DomainOK))
	fmt.Fprintf(&b, "- Exercise passes under Enforcing: %s\n", okStr(res.ExerciseOK))
	fmt.Fprintf(&b, "- Residual AVC denials: %d\n", len(res.ResidualAVCs))
	for _, d := range res.ResidualAVCs {
		fmt.Fprintf(&b, "  - `%s` %s:%s %v (path=%s name=%s)\n", d.SourceType, d.TargetType, d.Class, d.Perms, d.Path, d.Name)
	}

	b.WriteString("\n## Static least-privilege checks\n\n")
	for _, c := range res.StaticChecks {
		fmt.Fprintf(&b, "- %s: %s\n", c.Name, okStr(c.Passed))
		if !c.Passed {
			fmt.Fprintf(&b, "  - detail: `%s`\n", firstLine(c.Detail))
		}
	}

	if len(res.AcceptedExceptions) > 0 {
		b.WriteString("\n## ⚠ Accepted exceptions (least-privilege deviations, consciously granted)\n\n")
		for _, c := range res.AcceptedExceptions {
			fmt.Fprintf(&b, "- %s — `%s`\n", c.Name, firstLine(c.Detail))
		}
	}
	if len(res.Flags) > 0 {
		b.WriteString("\n## ⚠ Rules requiring human review\n\n")
		for _, f := range res.Flags {
			fmt.Fprintf(&b, "- %s — `%s`\n", f.Reason, f.Rule.Render())
		}
	}
	b.WriteString("\n## Grant coverage vs. static import analysis\n\n")
	b.WriteString("_Predicted behaviors (from ELF imports) and whether the final policy grants them. " +
		"A granted prediction is NOT proof the exercise drove it; an ungranted one likely means the exercise omitted it._\n\n")
	if !res.StaticImports {
		b.WriteString("Entrypoints are statically linked; import-based prediction unavailable " +
			"(syscall-site disassembly is the follow-up for this case).\n")
	} else if len(res.Predictions) == 0 {
		b.WriteString("No policy-relevant imports detected.\n")
	} else {
		for _, pr := range res.Predictions {
			gap := ""
			for _, g := range res.UngrantedPreds {
				if g.Feature == pr.Feature {
					gap = " — **not granted by the final policy: exercise likely does not cover this**"
				}
			}
			fmt.Fprintf(&b, "- `%s` (%s)%s\n", pr.Feature, pr.Reason, gap)
		}
	}

	if res.Party != "" || len(res.ConformanceUndecl)+len(res.ConformanceUnexer) > 0 || res.ConformanceFatal != "" {
		party := res.Party
		if party == "" {
			party = "third"
		}
		fmt.Fprintf(&b, "\n## Supply-chain conformance (party: %s)\n\n", party)
		if res.ConformanceFatal != "" {
			fmt.Fprintf(&b, "**VERDICT: FAIL** — %s\n\n", res.ConformanceFatal)
		}
		if len(res.ConformanceUndecl) > 0 {
			b.WriteString("Observed but not declared/baselined:\n\n")
			for _, f := range res.ConformanceUndecl {
				fmt.Fprintf(&b, "- %s\n", f)
			}
		}
		if len(res.ConformanceUnexer) > 0 {
			b.WriteString("\nDeclared but never observed (coverage gap or over-declaration):\n\n")
			for _, u := range res.ConformanceUnexer {
				fmt.Fprintf(&b, "- %s\n", u)
			}
		}
		if res.ConformanceFatal == "" && len(res.ConformanceUndecl)+len(res.ConformanceUnexer) == 0 {
			b.WriteString("Observed behavior matches the declaration/baseline exactly.\n")
		}
	}

	if len(res.Collisions) > 0 {
		b.WriteString("\n## ⚠ Base-policy path collisions\n\nThese paths are already claimed by the distro policy. hardener does not " +
			"redeclare them (semodule would reject the module), so the application's files there keep the base label:\n\n")
		for _, c := range res.Collisions {
			fmt.Fprintf(&b, "- %s\n", c.Render())
		}
	}
	if len(res.Relabels) > 0 {
		b.WriteString("\n## Labeling fixes applied (restorecon, not policy)\n\n")
		for _, rl := range res.Relabels {
			fmt.Fprintf(&b, "- `%s`: %s → %s\n", rl.Path, rl.ObservedType, rl.ExpectedType)
		}
	}
	if res.RPMPath != "" {
		fmt.Fprintf(&b, "\n## Artifact\n\n- `%s`\n", res.RPMPath)
	}
	b.WriteString("\n## Generated policy (.te)\n\n```\n" + res.FinalTE + "```\n")
	b.WriteString("\n## File contexts (.fc)\n\n```\n" + res.FinalFC + "```\n")
	return b.String()
}

func okStr(ok bool) string {
	if ok {
		return "✅"
	}
	return "❌"
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i] + " …"
	}
	return s
}
