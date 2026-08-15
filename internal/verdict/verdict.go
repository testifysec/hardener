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
	"regexp"

	"github.com/testifysec/hardener/internal/pipeline"
	"github.com/testifysec/hardener/internal/policy"
)

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

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
	Rounds           []Round       `json:"rounds"`
	RulesSynthesized int           `json:"rulesSynthesized"`
	Flagged          []FlaggedRule `json:"flagged,omitempty"`
	Relabels         int           `json:"relabels"`
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
	st, err := BuildOrErr(res, env, extra)
	if err != nil {
		panic(err)
	}
	return st
}

// BuildOrErr maps a pipeline result to the statement. Every subject digest is
// validated as 64-hex sha256 — a malformed or empty digest fails construction
// rather than silently binding the attestation to nothing (review finding).
// The entrypoint bytes are subjects too, binding the verdict to exactly what
// was installed and exercised, not just the generated policy text.
func BuildOrErr(res *pipeline.Result, env Env, extra []Subject) (Statement, error) {
	app := policy.SafeName(res.Target.Name)
	subjects := make([]wireSubject, 0, len(extra)+4)
	add := func(name, digest string) error {
		if !sha256Re.MatchString(digest) {
			return fmt.Errorf("subject %q: invalid sha256 digest %q (want 64 lowercase hex)", name, digest)
		}
		subjects = append(subjects, wireSubject{Name: name, Digest: map[string]string{"sha256": digest}})
		return nil
	}
	for _, s := range extra {
		if err := add(s.Name, s.SHA256); err != nil {
			return Statement{}, err
		}
	}
	for path, digest := range res.EntrypointDigests {
		if err := add(path, digest); err != nil {
			return Statement{}, err
		}
	}
	if res.FinalTE != "" {
		_ = add(app+".te", sum(res.FinalTE))
	}
	if res.FinalFC != "" {
		_ = add(app+".fc", sum(res.FinalFC))
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
	for _, g := range res.UngrantedPreds {
		p.Coverage.Gaps = append(p.Coverage.Gaps, g.Feature)
	}
	for _, c := range res.Collisions {
		p.Collisions = append(p.Collisions, c.Render())
	}

	return Statement{
		Type: "https://in-toto.io/Statement/v1", Subject: subjects,
		PredicateType: PredicateType, Predicate: p,
	}, nil
}

// RPMSubjectName extracts the basename of the built RPM for subject naming.
func RPMSubjectName(rpmPath string) string { return filepath.Base(rpmPath) }

// verdictOf derives the verdict from every gate independently — never from a
// single summary boolean alone. A verdict-only deploy gate must fail closed
// on any gate failure (finding from PR review: a pass with DomainOK=false
// would let an unconfined service through).
func verdictOf(res *pipeline.Result) string {
	if failureOf(res) != "" {
		return "fail"
	}
	if len(res.AcceptedExceptions) > 0 || len(res.Flags) > 0 {
		// Flags reaching a passing verdict means they were consciously
		// accepted; the verdict still discloses the deviation.
		return "pass-with-exceptions"
	}
	return "pass"
}

func failureOf(res *pipeline.Result) string {
	switch {
	case res.FailureReason != "":
		return res.FailureReason
	case res.ConformanceFatal != "":
		return res.ConformanceFatal
	case !res.DomainOK:
		return "process does not run in the generated domain"
	case !res.ExerciseOK:
		return "workload exercise failed under enforcement"
	case len(res.ResidualAVCs) > 0:
		return fmt.Sprintf("%d residual denials under enforcement", len(res.ResidualAVCs))
	case !res.EnforceOK:
		return "enforcing verification failed"
	case len(res.Flags) > 0 && !res.FlagsAccepted:
		return fmt.Sprintf("%d review-flagged rules were not accepted (--accept-flagged records the review decision)", len(res.Flags))
	}
	for _, c := range res.StaticChecks {
		if !c.Passed {
			return "static least-privilege check failed: " + c.Name
		}
	}
	return ""
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
