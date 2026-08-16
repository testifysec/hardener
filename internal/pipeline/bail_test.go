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
	// seq scripts a substring whose response CHANGES across calls: each match
	// pops the next entry (the last entry sticks). Used to model a process whose
	// identity differs between the pre- and post-exercise capture. Takes
	// precedence over responses on a match.
	seq    map[string][]string
	seqPos map[string]int
	failOn []string
	calls  []string
	// duplicateBarrier makes the audit tail echo the write-barrier token TWICE,
	// modeling a guest that replayed the boundary to truncate the window early.
	duplicateBarrier bool
}

func (f *fakeRunner) Run(script string) (string, error) {
	f.calls = append(f.calls, script)
	for _, pattern := range f.failOn {
		if strings.Contains(script, pattern) {
			return "", errors.New("exit status 1")
		}
	}
	// Model the audit read: the exercise parses only THROUGH the ordered sentinel,
	// so a realistic audit-log tail must CONTAIN it. The barrier token is now an
	// unguessable crypto/rand nonce (round 71) — it can no longer be derived from
	// `stat` output — so echo back the exact token the exercise just emitted via
	// `auditctl -m`, after whatever slice the test injected.
	if strings.Contains(script, "tail -c") && strings.Contains(script, "audit.log") {
		slice := f.staticMatch(script)
		if slice != "" && !strings.HasSuffix(slice, "\n") {
			slice += "\n"
		}
		tok := f.emittedBarrier()
		if f.duplicateBarrier {
			return slice + tok + "\ntype=AVC hidden-by-early-boundary\n" + tok + "\n", nil
		}
		return slice + tok + "\n", nil
	}
	// Stateful sequence responses win over static ones, longest match first.
	seqBest := ""
	for pattern := range f.seq {
		if strings.Contains(script, pattern) && len(pattern) > len(seqBest) {
			seqBest = pattern
		}
	}
	if seqBest != "" {
		if f.seqPos == nil {
			f.seqPos = map[string]int{}
		}
		q := f.seq[seqBest]
		i := f.seqPos[seqBest]
		if i >= len(q)-1 {
			i = len(q) - 1
		}
		f.seqPos[seqBest]++
		return q[i], nil
	}
	return f.staticMatch(script), nil
}

// emittedBarrier returns the most recent `auditctl -m 'hardener-barrier-...'`
// token the code under test emitted. The token is an unguessable nonce, so the
// fake cannot reconstruct it — it must echo back what was actually sent.
func (f *fakeRunner) emittedBarrier() string {
	for i := len(f.calls) - 1; i >= 0; i-- {
		c := f.calls[i]
		if !strings.Contains(c, "auditctl -m") || !strings.Contains(c, "hardener-barrier-") {
			continue
		}
		start := strings.Index(c, "hardener-barrier-")
		tok := c[start:]
		if q := strings.IndexByte(tok, '\''); q >= 0 {
			tok = tok[:q]
		}
		return strings.TrimSpace(tok)
	}
	return ""
}

// staticMatch returns the response whose key is the longest substring of script
// (most specific wins) — deterministic, and lets a command containing several
// keys resolve to the intended response. No seq side effects.
func (f *fakeRunner) staticMatch(script string) string {
	best, bestOut := "", ""
	for pattern, out := range f.responses {
		if strings.Contains(script, pattern) && len(pattern) > len(best) {
			best, bestOut = pattern, out
		}
	}
	return bestOut
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
			"getenforce":               "Enforcing\nactive",
			"stat -c '%s %i'":          "0 4242",
			"stat -c '%s'":             "0",
			"stat -c '%i'":             "4242",
			"stat -c %h":               "1",
			"auditctl -s":              "enabled 1 lost 0 backlog 0",
			"semodule -l":              "base\nselinux-policy\nunconfined\n",
			"grep -Fc":                 "1",
			"is-active widget.service": "inactive",
			"cat /etc/redhat-release":  "AlmaLinux release 9.4",
			"uname -r":                 "5.14.0-427.el9.x86_64",
			"rpm -q selinux-policy":    "selinux-policy-38.1.35-2.el9.noarch",
			"systemctl restart":        "",
			"sha256sum":                "abababababababababababababababababababababababababababababababab  /opt/widget/bin/widgetd",
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
