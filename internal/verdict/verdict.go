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
	"sort"
	"strings"

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
	// ExerciseEnforcing is the COMBINED gate: the workload ran successfully AND
	// it ran under verified enforcement. It was previously populated from
	// res.ExerciseOK alone, so a run whose enforcement verification FAILED but
	// whose exercise happened to succeed serialized this gate as true — the signed
	// predicate advertised "exercised under enforcement" for a policy that never
	// reached a verified enforcing state (review finding — round 68). Both inputs
	// are now serialized separately as well, so a consumer can tell the two apart.
	ExerciseEnforcing  bool          `json:"exerciseEnforcing"`
	ExerciseSucceeded  bool          `json:"exerciseSucceeded"`
	EnforcementProven  bool          `json:"enforcementProven"`
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
	// DeclaredEntrypoints are every entrypoint the profile labels <app>_exec_t and
	// binds as a signed subject. ObservedEntrypoints are the subset actually seen
	// EXECUTING in the app's domain under enforcement (the unit's MainPID binary).
	// They differ legitimately for multi-binary apps whose helpers never become
	// MainPID, so the difference is DISCLOSED rather than rejected — but it must be
	// disclosed, or a passing verdict reads as if every declared entrypoint had run
	// confined when only one was proven to (review finding — round 72).
	DeclaredEntrypoints []string `json:"declaredEntrypoints,omitempty"`
	ObservedEntrypoints []string `json:"observedEntrypoints,omitempty"`
	// BaseGrants are the refpolicy interfaces every generated domain receives
	// UNCONDITIONALLY (shell/bin execution, /etc and /usr reads, generic cert
	// access, syslog). They produce no AVCs, so they are never "observed" —
	// the verdict discloses them explicitly as review-required privilege, so a
	// pass cannot imply these were exercised and minimized (review finding).
	BaseGrants []string `json:"baseGrants,omitempty"`
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
	// One canonical party value. res.Target.Party is the manifest authority and
	// is what gets SIGNED into the predicate; res.Party is a second field the
	// caller fills during conformance and can be empty or, if mis-wired, differ.
	// Reject a disagreement loudly rather than sign one party while fail-closing
	// on another (review finding).
	if res.Party != "" && res.Party != res.Target.Party {
		return Statement{}, fmt.Errorf("inconsistent party: signed target says %q but conformance says %q", res.Target.Party, res.Party)
	}
	subjects := make([]wireSubject, 0, len(extra)+4)
	seenNames := map[string]bool{}
	add := func(name, digest string) error {
		if !sha256Re.MatchString(digest) {
			return fmt.Errorf("subject %q: invalid sha256 digest %q (want 64 lowercase hex)", name, digest)
		}
		if seenNames[name] {
			return fmt.Errorf("duplicate subject name %q — refusing an ambiguous attestation", name)
		}
		seenNames[name] = true
		subjects = append(subjects, wireSubject{Name: name, Digest: map[string]string{"sha256": digest}})
		return nil
	}
	// The ONLY authoritative extra subject is the built RPM. An arbitrary caller-
	// provided extra would otherwise be certified under a passing entrypoint-bound
	// verdict, letting the attestation vouch for an unrelated artifact (review
	// finding). Every extra must match the built RPM's name AND its computed digest.
	wantRPM := ""
	if res.RPMPath != "" {
		wantRPM = RPMSubjectName(res.RPMPath)
	}
	for _, s := range extra {
		if wantRPM == "" || s.Name != wantRPM || s.SHA256 != res.RPMSHA256 {
			return Statement{}, fmt.Errorf("extra subject %q@%s is not the built RPM (%q@%s) — refusing to certify an unrelated artifact", s.Name, s.SHA256, wantRPM, res.RPMSHA256)
		}
		if err := add(s.Name, s.SHA256); err != nil {
			return Statement{}, err
		}
	}
	// Sorted so identical inputs produce byte-identical statements and DSSE
	// signatures — map iteration order is otherwise random (review finding).
	epPaths := make([]string, 0, len(res.EntrypointDigests))
	for path := range res.EntrypointDigests {
		epPaths = append(epPaths, path)
	}
	sort.Strings(epPaths)
	for _, path := range epPaths {
		if err := add(path, res.EntrypointDigests[path]); err != nil {
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
			ExerciseEnforcing: res.ExerciseOK && res.EnforceOK,
			ExerciseSucceeded: res.ExerciseOK,
			EnforcementProven: res.EnforceOK,
			DomainProof:       res.DomainOK,
			ResidualDenials:   len(res.ResidualAVCs),
		},
		Conformance: Conformance{
			Party: res.Target.Party, Undeclared: res.ConformanceUndecl,
			Unexercised: res.ConformanceUnexer, Fatal: res.ConformanceFatal,
		},
		Coverage: Coverage{
			StaticImports:       res.StaticImports,
			BaseGrants:          append([]string(nil), policy.BaseInterfaces...),
			DeclaredEntrypoints: append([]string(nil), res.EntrypointPaths...),
			ObservedEntrypoints: append([]string(nil), res.ObservedEntrypoints...),
		},
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

	// A passing verdict must bind to the exercised artifact — the policy RPM
	// or the entrypoint bytes — not only the .te/.fc policy text. Otherwise
	// the attestation certifies a policy with no link to what gets installed.
	if p.Verdict != "fail" {
		// The exercised APPLICATION bytes must be bound: a digest for EVERY
		// resolved entrypoint, and no unrelated path. The built RPM is the
		// generated SELinux POLICY package (compiled .pp + %post), NOT the
		// application — so it cannot substitute (the old `|| res.RPMPath != ""`
		// bound the verdict to the policy alone, letting a CHANGED application
		// artifact reuse the attestation). A mere non-empty check is also
		// insufficient: an OMITTED entrypoint could change without invalidating
		// the signature (review finding). Validate the digest keys against the
		// resolved entrypoint set the pipeline recorded: every one present, none
		// extra. The RPM, when produced, is ADDITIONALLY required below.
		if len(res.EntrypointPaths) == 0 || len(res.EntrypointDigests) == 0 {
			return Statement{}, fmt.Errorf("passing verdict has no verified entrypoint digests — the attestation would bind the generated policy package but not the application bytes exercised; refusing")
		}
		expected := make(map[string]bool, len(res.EntrypointPaths))
		for _, e := range res.EntrypointPaths {
			expected[e] = true
			if res.EntrypointDigests[e] == "" {
				return Statement{}, fmt.Errorf("passing verdict is missing a bound digest for resolved entrypoint %q — every exercised entrypoint must be bound; refusing", e)
			}
		}
		for k := range res.EntrypointDigests {
			if !expected[k] {
				return Statement{}, fmt.Errorf("passing verdict binds an entrypoint digest for %q, which is not in the resolved entrypoint set — refusing to attest an unrelated path", k)
			}
		}
		// Whenever an RPM was actually produced, it MUST be among the subjects.
		// The distributed package (compiled policy + %post scriptlets) is what
		// gets installed; a passing attestation that binds only the entrypoint
		// bytes leaves that package uncertified (review finding). Entrypoint
		// digests do not substitute for the RPM subject.
		if res.RPMPath != "" {
			want := RPMSubjectName(res.RPMPath)
			var boundDigest string
			for _, s := range subjects {
				if s.Name == want {
					boundDigest = s.Digest["sha256"]
					break
				}
			}
			if boundDigest == "" {
				return Statement{}, fmt.Errorf("passing verdict produced RPM %q but it is not a bound subject; refusing to attest a package unbound to its policy", want)
			}
			// The bound digest must equal the digest the verifier COMPUTED for the
			// built RPM. Matching only the basename let a valid-but-wrong digest
			// (a different package under the same name) receive a passing
			// attestation (review finding).
			if res.RPMSHA256 == "" {
				return Statement{}, fmt.Errorf("RPM %q was produced but its authoritative sha256 was not computed; refusing to attest an unverifiable package", want)
			}
			if boundDigest != res.RPMSHA256 {
				return Statement{}, fmt.Errorf("RPM subject %q digest %s does not match the computed package digest %s; refusing to attest a mismatched package", want, boundDigest, res.RPMSHA256)
			}
		}
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
	if len(res.AcceptedExceptions) > 0 || len(res.Flags) > 0 || len(res.Collisions) > 0 {
		// Flags reaching a passing verdict means they were consciously
		// accepted; the verdict still discloses the deviation. A base-policy
		// COLLISION is the same shape of disclosed deviation: the pipeline
		// deliberately recovers from a non-entrypoint collision (drops the
		// path, the app runs less-confined there) — that is a real reduction
		// in confinement and must surface in the verdict STATUS, not sit
		// silently in the predicate body while the top line reads a clean
		// "pass" (review finding). Entrypoint collisions already fail earlier,
		// so any collision reaching here is a recovered one; forcing a hard
		// FAIL instead would reverse the deliberate recoverable-collision
		// design and is a product-semantics call for the owner, not this loop.
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
	case len(res.ConformanceUndecl) > 0 && (res.Target.Party == "second" || res.Target.Party == "first"):
		// Defense in depth against an inconsistent result: undeclared behavior is
		// fatal for a first/second-party artifact, so fail closed on the
		// structured ConformanceUndecl data even if the fatal-summary string was
		// never set (review finding — the two could disagree and pass). Keyed on
		// res.Target.Party — the SAME party value that gets SIGNED into the
		// predicate — not res.Party, a second field that can be empty or disagree
		// (review finding: a signed "second" with an empty res.Party passed).
		return "undeclared behavior for a " + res.Target.Party + "-party artifact: " + strings.Join(res.ConformanceUndecl, ", ")
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
	case len(res.Collisions) > 0 && !res.FlagsAccepted:
		// A base-policy collision REMOVES the colliding path from the generated
		// file contexts (GenerateFCExcluding), so part of the requested confinement
		// is silently absent. Unlike a flagged rule, this reached a passing
		// verdict with no explicit acceptance (review finding). Treat it like a
		// flag: fail closed unless the operator consciously accepts the reduced
		// confinement (--accept-flagged), which still discloses it in the verdict.
		return fmt.Sprintf("%d base-policy collision(s) removed declared confinement and were not accepted (--accept-flagged records the review decision)", len(res.Collisions))
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
