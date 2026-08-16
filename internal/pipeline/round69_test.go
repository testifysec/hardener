package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/target"
)

// Round 69: the start-barrier sentinel text is CONSTANT per target and the audit
// log is persistent, so from the second exercise onward a mere "is it present?"
// check is satisfied instantly by an OLD record — the barrier never waits, and
// the round-68 fix silently stops working. The wait must key on the count
// INCREASING past the pre-emit count.
func TestStartBarrierWaitsForCountIncrease(t *testing.T) {
	tgt := &target.Target{
		Name: "widget", Unit: "widget.service", Install: "true",
		Exercise: "true", Executables: []string{"/opt/widget/bin/widgetd"},
	}
	f := &fakeRunner{
		responses: map[string]string{
			"stat -c '%s %i'":           "100 4242",
			"stat -c '%s'":              "100",
			"stat -c '%i'":              "4242",
			"auditctl -s":               "enabled 1 lost 0 backlog 0",
			"is-active widget.service":  "inactive",
			"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
		},
		seq: map[string][]string{
			// A PRIOR run already left 3 records. The pre-emit count is 3; the barrier
			// must keep polling until it reads 4, then the end barrier reads non-zero.
			"grep -Fc": {"3", "3", "4", "1"},
		},
	}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err != nil {
		t.Fatalf("exercise must succeed: %v", err)
	}
	// The pre-emit count must be taken BEFORE auditctl -m, and the barrier must
	// poll at least once more after emitting (proving it did not accept the stale
	// count of 3 as satisfaction).
	emit, preCount, postPolls := -1, -1, 0
	for i, c := range f.calls {
		isCount := strings.Contains(c, "grep -Fc") && strings.Contains(c, "hardener-start-widget")
		if isCount && preCount < 0 {
			preCount = i
		}
		if emit < 0 && strings.Contains(c, "auditctl -m") && strings.Contains(c, "hardener-start-widget") {
			emit = i
		}
		if isCount && emit >= 0 && i > emit {
			postPolls++
		}
	}
	if preCount < 0 || emit < 0 {
		t.Fatal("exercise must count the start sentinel and then emit it")
	}
	if preCount > emit {
		t.Error("the pre-emit occurrence count must be taken BEFORE auditctl -m")
	}
	if postPolls < 2 {
		t.Errorf("the barrier must keep polling until the count increases (post-emit polls=%d, want >=2)", postPolls)
	}
}

// Round 69: %post cannot roll back the RPM transaction — rpm has already
// committed the payload and the new NEVRA before %post runs, so a failure there
// leaves files on disk and a DB entry that makes retrying the same NEVRA a no-op.
// The read-only, ABORTABLE preflight (foreign same-name module / foreign owner of
// our port type) must therefore also run in %pre, where a non-zero exit aborts the
// transaction cleanly before any commit.
func TestSpecPreAbortsFreshInstallPreflight(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Ports:       []profile.Port{{Proto: "tcp", Port: 8443}},
	}
	spec := GenerateSpec(p, "20260101000000")
	pre := spec[strings.Index(spec, "\n%pre\n"):]
	pre = pre[:strings.Index(pre, "\n%post\n")]
	for _, want := range []string{
		`if [ "$1" = 1 ]; then`,
		"a SELinux module named widget already exists",
		"already has mappings but this is a fresh install",
		`awk -v t=widget_port_t '$1==t{f=1} END{exit !f}'`,
	} {
		if !strings.Contains(pre, want) {
			t.Errorf("pre scriptlet missing abortable preflight %q", want)
		}
	}
	// The preflight must be read-only: no activation/mutation belongs in %pre.
	// Check CODE lines only — the comments legitimately mention these commands.
	var code strings.Builder
	for _, ln := range strings.Split(pre, "\n") {
		if s := strings.TrimSpace(ln); s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		code.WriteString(ln)
		code.WriteString("\n")
	}
	for _, forbidden := range []string{"semodule -i", "semanage port -a", "restorecon -RF"} {
		if strings.Contains(code.String(), forbidden) {
			t.Errorf("pre scriptlet must not mutate state (found %q)", forbidden)
		}
	}
}
