// Package verdict renders a verified run as an unsigned in-toto Statement.
// hardener deliberately does NOT sign: signing means key management, and key
// management belongs to the factory's existing attestation rails (CI/Lock).
// The tool emits the claim; the wrapper owns the trust:
//
//	cilock run --step confine --workload manual -- hardener run --vm verifier target.yaml
//
// The predicate is the machine-readable form of the report: verdict, gates,
// observation summary, conformance outcome, coverage gaps, verifier baseline.
// A deploy gate needs nothing else to decide.
package verdict

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/testifysec/hardener/internal/pipeline"
	"github.com/testifysec/hardener/internal/policy"
)

// PredicateType identifies this attestation's schema.
const PredicateType = "https://testifysec.com/attestations/hardener-verdict/v0.1"

// Subject is one artifact the statement binds to.
type Subject struct {
	Name   string `json:"name"`
	SHA256 string `json:"-"`
}

type wireSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Env describes the verifier baseline the claim is scoped to.
type Env struct {
	Distro        string `json:"distro,omitempty"`
	Kernel        string `json:"kernel,omitempty"`
	Mode          string `json:"selinuxMode,omitempty"`
	PolicyPackage string `json:"policyPackage,omitempty"`
}

// Statement is an in-toto v1 Statement carrying the hardener predicate.
type Statement struct {
	Type          string        `json:"_type"`
	Subject       []wireSubject `json:"subject"`
	PredicateType string        `json:"predicateType"`
	Predicate     Predicate     `json:"predicate"`
}

// Predicate is the verdict payload.
type Predicate struct {
	Verdict       string      `json:"verdict"` // pass | pass-with-exceptions | fail
	FailureReason string      `json:"failureReason,omitempty"`
	Domain        string      `json:"domain"`
	Target        TargetInfo  `json:"target"`
	Verifier      Env         `json:"verifier"`
	Gates         Gates       `json:"gates"`
	Observation   Observation `json:"observation"`
	Conformance   Conformance `json:"conformance"`
	Coverage      Coverage    `json:"coverage"`
	Collisions    []string    `json:"collisions,omitempty"`
}

type TargetInfo struct {
	Name    string `json:"name"`
	Party   string `json:"party,omitempty"`
	License string `json:"license,omitempty"`
	Source  string `json:"source,omitempty"`
	Unit    string `json:"unit,omitempty"`
}

type Gates struct {
	ExerciseEnforcing  bool          `json:"exerciseEnforcing"`
	DomainProof        bool          `json:"domainProof"`
	ResidualDenials    int           `json:"residualDenials"`
	StaticChecks       []CheckResult `json:"staticChecks,omitempty"`
	AcceptedExceptions []CheckResult `json:"acceptedExceptions,omitempty"`
}

type CheckResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

type Observation struct {
	Rounds          []Round       `json:"rounds"`
	RulesSynthesized int          `json:"rulesSynthesized"`
	Flagged         []FlaggedRule `json:"flagged,omitempty"`
	Relabels        int           `json:"relabels"`
}

type Round struct {
	Denials    int  `json:"denials"`
	NewRules   int  `json:"newRules"`
	Relabels   int  `json:"relabels"`
	ExerciseOK bool `json:"exerciseOk"`
}

type FlaggedRule struct {
	Reason string `json:"reason"`
	Rule   string `json:"rule"`
}

type Conformance struct {
	Party       string   `json:"party,omitempty"`
	Undeclared  []string `json:"undeclared,omitempty"`
	Unexercised []string `json:"unexercised,omitempty"`
	Fatal       string   `json:"fatal,omitempty"`
}

type Coverage struct {
	StaticImports bool     `json:"staticImports"`
	Predictions   []string `json:"predictions,omitempty"`
	Gaps          []string `json:"gaps,omitempty"`
}

// Build maps a pipeline result to the statement. Extra subjects (the RPM,
// hashed in the verifier) are passed in; the .te/.fc are hashed here since
// their content lives in the result.
func Build(res *pipeline.Result, env Env, extra []Subject) Statement {
	app := policy.SafeName(res.Target.Name)
	subjects := make([]wireSubject, 0, len(extra)+2)
	for _, s := range extra {
		if s.SHA256 != "" {
			subjects = append(subjects, wireSubject{Name: s.Name, Digest: map[string]string{"sha256": s.SHA256}})
		}
	}
	if res.FinalTE != "" {
		subjects = append(subjects, wireSubject{Name: app + ".te", Digest: map[string]string{"sha256": sum(res.FinalTE)}})
	}
	if res.FinalFC != "" {
		subjects = append(subjects, wireSubject{Name: app + ".fc", Digest: map[string]string{"sha256": sum(res.FinalFC)}})
	}

	p := Predicate{
		Verdict:       verdictOf(res),
		FailureReason: failureOf(res),
		Domain:        res.Domain,
		Target: TargetInfo{
			Name: res.Target.Name, Party: res.Target.Party,
			License: res.Target.License, Source: res.Target.Source, Unit: res.Target.Unit,
		},
		Verifier: env,
		Gates: Gates{
			ExerciseEnforcing: res.ExerciseOK,
			DomainProof:       res.DomainOK,
			ResidualDenials:   len(res.ResidualAVCs),
		},
		Conformance: Conformance{
			Party: res.Party, Undeclared: res.ConformanceUndecl,
			Unexercised: res.ConformanceUnexer, Fatal: res.ConformanceFatal,
		},
		Coverage: Coverage{StaticImports: res.StaticImports},
	}
	for _, c := range res.StaticChecks {
		p.Gates.StaticChecks = append(p.Gates.StaticChecks, CheckResult{Name: c.Name, Passed: c.Passed, Detail: c.Detail})
	}
	for _, c := range res.AcceptedExceptions {
		p.Gates.AcceptedExceptions = append(p.Gates.AcceptedExceptions, CheckResult{Name: c.Name, Passed: false, Detail: c.Detail})
	}
	relabels := 0
	for _, r := range res.Rounds {
		p.Observation.Rounds = append(p.Observation.Rounds, Round(r))
		relabels += r.Relabels
	}
	p.Observation.Relabels = relabels
	p.Observation.RulesSynthesized = len(res.FinalRules)
	for _, f := range res.Flags {
		p.Observation.Flagged = append(p.Observation.Flagged, FlaggedRule{Reason: f.Reason, Rule: f.Rule.Render()})
	}
	for _, pr := range res.Predictions {
		p.Coverage.Predictions = append(p.Coverage.Predictions, fmt.Sprintf("%s (%s)", pr.Feature, pr.Reason))
	}
	for _, g := range res.CoverageGaps {
		p.Coverage.Gaps = append(p.Coverage.Gaps, g.Feature)
	}
	for _, c := range res.Collisions {
		p.Collisions = append(p.Collisions, c.Render())
	}

	return Statement{
		Type: "https://in-toto.io/Statement/v1", Subject: subjects,
		PredicateType: PredicateType, Predicate: p,
	}
}

// RPMSubjectName extracts the basename of the built RPM for subject naming.
func RPMSubjectName(rpmPath string) string { return filepath.Base(rpmPath) }

func verdictOf(res *pipeline.Result) string {
	if res.FailureReason != "" || !res.EnforceOK || res.ConformanceFatal != "" {
		return "fail"
	}
	if len(res.AcceptedExceptions) > 0 {
		return "pass-with-exceptions"
	}
	return "pass"
}

func failureOf(res *pipeline.Result) string {
	if res.FailureReason != "" {
		return res.FailureReason
	}
	if res.ConformanceFatal != "" {
		return res.ConformanceFatal
	}
	if !res.EnforceOK {
		return "enforcing verification failed"
	}
	return ""
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
