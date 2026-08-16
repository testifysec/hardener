package verdict

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/pipeline"
	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/target"
)

func passingResult() *pipeline.Result {
	return &pipeline.Result{
		Target: &target.Target{Name: "widget", License: "open-source", Party: "second", Unit: "widget.service"},
		Domain: "widget_t",
		Rounds: []pipeline.RoundResult{
			{Denials: 4, NewRules: 2, Relabels: 1, ExerciseOK: true},
			{Denials: 0, NewRules: 0, Relabels: 0, ExerciseOK: true},
		},
		FinalTE: "policy_module(widget, 1.0.0)\n", FinalFC: "/opt/widget/bin/widgetd\t--\t...\n",
		Flags: []policy.Flag{{
			Reason: "privileged capability: setuid",
			Rule:   policy.AllowRule{Source: "widget_t", Target: "widget_t", Class: "capability", Perms: []string{"setuid"}},
		}},
		EnforceOK: true, DomainOK: true, ExerciseOK: true, FlagsAccepted: true,
		EntrypointDigests: map[string]string{"/usr/sbin/widgetd": "abababababababababababababababababababababababababababababababab"},
		EntrypointPaths:   []string{"/usr/sbin/widgetd"},
		StaticChecks:      []pipeline.StaticCheck{{Name: "no shadow_t read/write", Passed: true}},
		// RPMPath is deliberately empty here: RPM-subject binding is exercised
		// where it matters (TestBuildStatementShape passes the RPM via extra,
		// TestPassingVerdictRequiresRPMSubjectWhenRPMProduced sets RPMPath). The
		// build requires an RPM subject only when RPMPath is set, so most pass
		// cases bind via the entrypoint digest above.
	}
}

func TestBuildStatementShape(t *testing.T) {
	r := passingResult()
	r.RPMPath = "/home/u/rpmbuild/RPMS/noarch/widget-selinux-1.0.0-1.el9.noarch.rpm"
	r.RPMSHA256 = "abababababababababababababababababababababababababababababababab"
	st := Build(r, Env{Distro: "AlmaLinux 9.8", Kernel: "5.14.0", Mode: "Enforcing", PolicyPackage: "selinux-policy-38"},
		[]Subject{{Name: "widget-selinux-1.0.0-1.el9.noarch.rpm", SHA256: "abababababababababababababababababababababababababababababababab"}})

	if st.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("statement type: %q", st.Type)
	}
	if st.PredicateType != PredicateType {
		t.Errorf("predicate type: %q", st.PredicateType)
	}
	// Subjects: the explicit RPM plus the hashed .te and .fc
	names := map[string]bool{}
	for _, s := range st.Subject {
		if s.Digest["sha256"] == "" {
			t.Errorf("subject %s missing digest", s.Name)
		}
		names[s.Name] = true
	}
	for _, want := range []string{"widget-selinux-1.0.0-1.el9.noarch.rpm", "widget.te", "widget.fc"} {
		if !names[want] {
			t.Errorf("missing subject %q (have %v)", want, names)
		}
	}
	// The fixture carries an accepted review flag, so the verdict discloses it.
	if st.Predicate.Verdict != "pass-with-exceptions" {
		t.Errorf("verdict: %q", st.Predicate.Verdict)
	}
	if st.Predicate.Target.Party != "second" || st.Predicate.Domain != "widget_t" {
		t.Errorf("target/domain: %+v", st.Predicate.Target)
	}
	if !st.Predicate.Gates.DomainProof || st.Predicate.Gates.ResidualDenials != 0 {
		t.Errorf("gates: %+v", st.Predicate.Gates)
	}
	if len(st.Predicate.Observation.Flagged) != 1 ||
		!strings.Contains(st.Predicate.Observation.Flagged[0].Rule, "setuid") {
		t.Errorf("flagged rules must carry the rendered rule: %+v", st.Predicate.Observation.Flagged)
	}
}

func TestVerdictStates(t *testing.T) {
	r := passingResult()
	r.AcceptedExceptions = []pipeline.StaticCheck{{Name: "no shadow_t read/write", Detail: "allow ..."}}
	if v := Build(r, Env{}, nil).Predicate.Verdict; v != "pass-with-exceptions" {
		t.Errorf("accepted exceptions: %q", v)
	}

	r = passingResult()
	r.ConformanceFatal = "observed behavior the supplier never declared: capability setuid"
	if v := Build(r, Env{}, nil).Predicate.Verdict; v != "fail" {
		t.Errorf("conformance fatal: %q", v)
	}

	r = passingResult()
	r.EnforceOK = false
	if v := Build(r, Env{}, nil).Predicate.Verdict; v != "fail" {
		t.Errorf("enforce failure: %q", v)
	}

	r = passingResult()
	r.FailureReason = "install: exploded"
	if v := Build(r, Env{}, nil).Predicate.Verdict; v != "fail" {
		t.Errorf("hard failure: %q", v)
	}
}

// The statement must serialize to spec-shaped JSON: _type, subject, predicateType.
func TestJSONWireFormat(t *testing.T) {
	st := Build(passingResult(), Env{Mode: "Enforcing"}, nil)
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"_type", "subject", "predicateType", "predicate"} {
		if _, ok := m[key]; !ok {
			t.Errorf("wire format missing %q: %s", key, raw)
		}
	}
	pred := m["predicate"].(map[string]any)
	if _, ok := pred["conformance"]; !ok {
		t.Errorf("predicate missing conformance block")
	}
}

// A base-policy collision REMOVES the colliding path from the generated file
// contexts, so part of the requested confinement is absent. Like a flagged rule,
// it must NOT reach a passing verdict without explicit acceptance: unaccepted →
// fail closed; accepted (--accept-flagged) → pass-with-exceptions, disclosed in
// the verdict status. (review findings — rounds 50, 59)
func TestCollisionsRequireAcceptance(t *testing.T) {
	col := []policy.Collision{{Path: "/var/lib/widget/shared", BaseType: "var_lib_t", WouldBeType: "widget_var_lib_t"}}

	// Unaccepted: fail closed.
	r := passingResult()
	r.FlagsAccepted = false
	r.Flags = nil // isolate the collision from the flag gate
	r.Collisions = col
	if v := Build(r, Env{}, nil).Predicate.Verdict; v != "fail" {
		t.Errorf("an unaccepted collision must fail closed, got %q", v)
	}

	// Accepted: pass-with-exceptions, disclosed in the status.
	r = passingResult() // passingResult sets FlagsAccepted: true
	r.Collisions = col
	if v := Build(r, Env{}, nil).Predicate.Verdict; v != "pass-with-exceptions" {
		t.Errorf("an accepted collision must disclose as pass-with-exceptions, got %q", v)
	}
}

// Round 68: the ExerciseEnforcing gate was populated from res.ExerciseOK alone,
// so a run whose ENFORCEMENT verification failed but whose exercise happened to
// succeed serialized the gate as true — the signed predicate advertised
// "exercised under enforcement" for policy that never reached a verified
// enforcing state. The gate must reflect BOTH, and both inputs must be
// serialized separately. (review finding)
func TestExerciseEnforcingGateRequiresBothStates(t *testing.T) {
	r := passingResult()
	r.EnforceOK = false // enforcement verification FAILED; exercise still ok
	g := Build(r, Env{}, nil).Predicate.Gates
	if g.ExerciseEnforcing {
		t.Error("ExerciseEnforcing must be false when enforcement was not proven")
	}
	if !g.ExerciseSucceeded {
		t.Error("ExerciseSucceeded must still report the exercise result")
	}
	if g.EnforcementProven {
		t.Error("EnforcementProven must be false when EnforceOK is false")
	}
	// The happy path still reports the gate as passing.
	ok := Build(passingResult(), Env{}, nil).Predicate.Gates
	if !ok.ExerciseEnforcing || !ok.ExerciseSucceeded || !ok.EnforcementProven {
		t.Errorf("a fully passing run must set all three gate fields, got %+v", ok)
	}
}

// Round 72: every declared entrypoint is labeled <app>_exec_t and bound as a
// signed subject, but only the unit's MainPID binary is verified running under
// enforcement. A passing verdict therefore read as if ALL of them had been
// exercised. Requiring the sets to be equal would be wrong (multi-binary apps
// legitimately have helpers that never become MainPID), so the predicate must
// DISCLOSE both sets. (review finding)
func TestCoverageDisclosesObservedVsDeclaredEntrypoints(t *testing.T) {
	r := passingResult()
	r.EntrypointPaths = []string{"/usr/sbin/widgetd", "/usr/libexec/widget-helper"}
	r.EntrypointDigests = map[string]string{
		"/usr/sbin/widgetd":          strings.Repeat("ab", 32),
		"/usr/libexec/widget-helper": strings.Repeat("cd", 32),
	}
	r.ObservedEntrypoints = []string{"/usr/sbin/widgetd"} // only MainPID ran
	cov := Build(r, Env{}, nil).Predicate.Coverage
	if len(cov.DeclaredEntrypoints) != 2 {
		t.Errorf("declared entrypoints = %v, want both", cov.DeclaredEntrypoints)
	}
	if len(cov.ObservedEntrypoints) != 1 || cov.ObservedEntrypoints[0] != "/usr/sbin/widgetd" {
		t.Errorf("observed entrypoints = %v, want only the MainPID binary", cov.ObservedEntrypoints)
	}
	// The un-exercised helper must NOT appear as observed.
	for _, o := range cov.ObservedEntrypoints {
		if o == "/usr/libexec/widget-helper" {
			t.Error("a helper that never ran as MainPID must not be reported as observed")
		}
	}
}
