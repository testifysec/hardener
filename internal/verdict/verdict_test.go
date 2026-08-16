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

// A recovered base-policy collision (non-entrypoint: the pipeline drops the
// path and the app runs less-confined there) must surface in the verdict STATUS
// as pass-with-exceptions, not sit silently in the predicate body under a clean
// "pass". Entrypoint collisions fail earlier, so any collision reaching the
// verdict is a recovered one — disclosed, not fatal. (review finding — round 50)
func TestCollisionsYieldPassWithExceptions(t *testing.T) {
	r := passingResult()
	r.Collisions = []policy.Collision{{Path: "/var/lib/widget/shared", BaseType: "var_lib_t", WouldBeType: "widget_var_lib_t"}}
	if v := Build(r, Env{}, nil).Predicate.Verdict; v != "pass-with-exceptions" {
		t.Errorf("a recovered collision must disclose in the verdict status, got %q", v)
	}
}
