package verdict

import (
	"testing"

	"github.com/testifysec/hardener/internal/avc"
	"github.com/testifysec/hardener/internal/pipeline"
)

// The verdict is what deploy gates trust. It must derive from EVERY gate
// independently — never from a single summary boolean that a future refactor
// might compute differently. One regression test per failure state.
func TestVerdictFailsClosedPerGate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*pipeline.Result)
	}{
		{"domain proof failed", func(r *pipeline.Result) { r.DomainOK = false }},
		{"exercise failed", func(r *pipeline.Result) { r.ExerciseOK = false }},
		{"residual denials", func(r *pipeline.Result) {
			r.ResidualAVCs = []avc.Denial{{SourceType: "widget_t", TargetType: "etc_t", Class: "file", Perms: []string{"write"}}}
		}},
		{"enforce summary false", func(r *pipeline.Result) { r.EnforceOK = false }},
		{"unaccepted static check failed", func(r *pipeline.Result) {
			r.StaticChecks = append(r.StaticChecks, pipeline.StaticCheck{
				Name: "no shadow_t read/write", Passed: false, Detail: "allow widget_t shadow_t:file read;",
			})
		}},
		{"conformance fatal", func(r *pipeline.Result) { r.ConformanceFatal = "drift" }},
		{"review flags not accepted", func(r *pipeline.Result) { r.FlagsAccepted = false }},
		{"stage failure", func(r *pipeline.Result) { r.FailureReason = "install: exploded" }},
	}
	for _, c := range cases {
		r := passingResult()
		c.mutate(r)
		st := Build(r, Env{}, nil)
		if st.Predicate.Verdict != "fail" {
			t.Errorf("%s: verdict %q, want fail", c.name, st.Predicate.Verdict)
		}
		if st.Predicate.FailureReason == "" {
			t.Errorf("%s: fail verdict must carry a reason", c.name)
		}
	}
}

// Accepted exceptions are the ONLY tolerated static-check deviation, and they
// downgrade to pass-with-exceptions, never plain pass.
func TestAcceptedExceptionsAreNotFailures(t *testing.T) {
	r := passingResult()
	r.RPMPath = "" // testing the verdict value, not RPM binding
	// passingResult() already carries an accepted review flag, which alone yields
	// pass-with-exceptions — so clear Flags to prove the AcceptedExceptions path is
	// what drives the verdict, not the pre-existing flag (review finding).
	r.Flags = nil
	r.FlagsAccepted = false
	if v := Build(r, Env{}, nil).Predicate.Verdict; v == "pass-with-exceptions" {
		t.Errorf("with Flags cleared, verdict should be plain pass before adding exceptions, got %q", v)
	}
	r.AcceptedExceptions = []pipeline.StaticCheck{{Name: "no shadow_t read/write", Detail: "allow ..."}}
	if v := Build(r, Env{}, nil).Predicate.Verdict; v != "pass-with-exceptions" {
		t.Errorf("an accepted exception alone must yield pass-with-exceptions, got %q", v)
	}
}
