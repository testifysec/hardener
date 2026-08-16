package pipeline

import (
	"errors"
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/target"
)

// fakeRunner scripts VM responses by substring match on the command.
// A pattern listed in failOn makes the matching script exit non-zero.
type fakeRunner struct {
	responses map[string]string
	failOn    []string
	calls     []string
}

func (f *fakeRunner) Run(script string) (string, error) {
	f.calls = append(f.calls, script)
	for _, pattern := range f.failOn {
		if strings.Contains(script, pattern) {
			return "", errors.New("exit status 1")
		}
	}
	for pattern, out := range f.responses {
		if strings.Contains(script, pattern) {
			return out, nil
		}
	}
	return "", nil
}

func (f *fakeRunner) WriteFile(path, content string) error {
	f.calls = append(f.calls, "WRITE "+path)
	return nil
}

func (f *fakeRunner) countCalls(substr string) int {
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

func testTarget() *target.Target {
	return &target.Target{
		Name:        "widget",
		Unit:        "widget.service",
		Install:     "true",
		Exercise:    "exit 1", // exercise always fails
		Executables: []string{"/opt/widget/bin/widgetd"},
	}
}

// An exercise that fails in a PERMISSIVE domain with zero denials cannot be a
// policy problem — permissive blocks nothing. Burning the remaining rounds
// wastes minutes per target and reports a misleading policy failure.
func TestBailsWhenPermissiveExerciseFailsWithNoDenials(t *testing.T) {
	f := &fakeRunner{
		responses: map[string]string{
			"getenforce":        "Enforcing\nactive",
			"stat -c '%s %i'":   "0 4242",
			"systemctl restart": "",
			"sha256sum":         "abababababababababababababababababababababababababababababababab  /opt/widget/bin/widgetd",
		},
		failOn: []string{"EXERCISE_MARKER"}, // the exercise script fails
	}
	tgt := testTarget()
	tgt.Exercise = "EXERCISE_MARKER"
	res := Run(f, tgt, Options{MaxRounds: 5})

	if !strings.Contains(res.FailureReason, "permissive") {
		t.Errorf("failure reason should identify this as a non-policy failure, got %q", res.FailureReason)
	}
	if len(res.Rounds) != 1 {
		t.Errorf("should bail after round 1, ran %d rounds", len(res.Rounds))
	}
	if res.EnforceOK {
		t.Error("must not report EnforceOK")
	}
}

// The verifier itself must be trustworthy: no Enforcing / no auditd ⇒ refuse.
func TestRefusesUntrustworthyVerifier(t *testing.T) {
	for _, precheck := range []string{"Permissive\nactive", "Enforcing\ninactive"} {
		f := &fakeRunner{responses: map[string]string{"getenforce": precheck}}
		res := Run(f, testTarget(), Options{})
		if !strings.Contains(res.FailureReason, "precheck") {
			t.Errorf("precheck %q: expected refusal, got %q", precheck, res.FailureReason)
		}
		if f.countCalls("systemctl restart") != 0 {
			t.Errorf("precheck %q: must not run the workload", precheck)
		}
	}
}
