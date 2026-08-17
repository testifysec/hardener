package pipeline

import (
	"strings"
	"testing"

	"github.com/testifysec/hardener/internal/policy"
	"github.com/testifysec/hardener/internal/profile"
	"github.com/testifysec/hardener/internal/target"
)

// Round 68: the caller loads our module and edits the permissive list right
// before exercise(), and those legitimate MAC_POLICY_LOAD records may still be
// queued. Taking the offset first let them land INSIDE the window, where the
// round-66 auditPolicyReloaded check reads them as tampering and fails a valid
// run. exercise() must emit an ordered START sentinel and wait for it BEFORE
// taking the offset, so the window begins strictly past our own setup.
func TestExerciseEmitsStartBarrierBeforeOffset(t *testing.T) {
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
			"grep -Fc":                  "1",
			"is-active widget.service":  "inactive",
			"systemctl show -p MainPID": "LABEL:system_u:system_r:widget_t:s0\nEXE:/opt/widget/bin/widgetd\nEXESHA:" + strings.Repeat("ab", 32),
		},
	}
	if _, _, _, err := exercise(f, tgt, "widget_t"); err != nil {
		t.Fatalf("exercise must succeed: %v", err)
	}
	startIdx, offsetIdx := -1, -1
	for i, c := range f.calls {
		if startIdx < 0 && strings.Contains(c, "auditctl -m") && strings.Contains(c, "hardener-start-widget") {
			startIdx = i
		}
		if offsetIdx < 0 && strings.Contains(c, "stat -c '%s %i'") {
			offsetIdx = i
		}
	}
	if startIdx < 0 {
		t.Fatal("exercise must emit an ordered START sentinel (auditctl -m hardener-start-...)")
	}
	if offsetIdx < 0 || startIdx > offsetIdx {
		t.Errorf("the start sentinel must be emitted BEFORE the audit offset is taken (start=%d offset=%d)", startIdx, offsetIdx)
	}
}

// Round 68: `make <app>.pp` is timestamp-driven, so a privileged exercise could
// pre-create the deterministic output with a future mtime and make would skip
// compilation, packaging unverified policy bytes. buildRPM must delete the build
// outputs first (unconditional rebuild) and assert the .pp actually exists after.
func TestBuildRPMForcesCleanPolicyRebuild(t *testing.T) {
	p := &profile.Profile{
		Name:        "widget",
		Executables: []string{"/opt/widget/bin/widgetd"},
		Paths:       []profile.PathAccess{{Path: "/var/lib/widget(/.*)?", Kind: "var_lib"}},
	}
	f := &fakeRunner{responses: map[string]string{
		"rpmbuild -bb": "Wrote: /root/rpmbuild/RPMS/noarch/widget-selinux-1.0-1.noarch.rpm",
	}}
	if _, err := buildRPM(f, p, "20260101000000", "(te)", policy.GenerateFC(p)); err != nil {
		t.Fatalf("buildRPM: %v", err)
	}
	var build string
	for _, c := range f.calls {
		if strings.Contains(c, "make -f /usr/share/selinux/devel/Makefile") {
			build = c
		}
	}
	if build == "" {
		t.Fatal("no policy build script was run")
	}
	if !strings.Contains(build, "rm -rf tmp widget.pp") {
		t.Error("the build must delete pre-existing outputs so make cannot skip compilation on a future-dated .pp")
	}
	if !strings.Contains(build, "test -f widget.pp") {
		t.Error("the build must assert the .pp exists after make")
	}
	if strings.Index(build, "rm -rf tmp") > strings.Index(build, "make -f") {
		t.Error("the removal must precede make")
	}
}
