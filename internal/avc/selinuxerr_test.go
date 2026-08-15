package avc

import "testing"

// systemd units with NoNewPrivileges=yes force SELinux to require a *bounded*
// transition (the new domain must be a subset of the old). A generated
// application domain never satisfies that, so the transition is refused and
// the service silently keeps running as init_t. The kernel reports this as
// SELINUX_ERR, not AVC — miss it and the failure looks like a mystery.
func TestParseBoundedTransitionError(t *testing.T) {
	line := `type=SELINUX_ERR msg=audit(1786737508.379:10286): op=security_bounded_transition seresult=denied oldcontext=system_u:system_r:init_t:s0 newcontext=system_u:system_r:splunkuf_t:s0`
	e, err := ParseTransitionError(line)
	if err != nil {
		t.Fatalf("ParseTransitionError: %v", err)
	}
	if e.OldType != "init_t" || e.NewType != "splunkuf_t" {
		t.Errorf("got %+v", e)
	}
	if e.Op != "security_bounded_transition" {
		t.Errorf("op: %q", e.Op)
	}
}

func TestParseTransitionErrorRejectsOtherRecords(t *testing.T) {
	for _, line := range []string{
		`type=AVC msg=audit(1.0:1): avc:  denied  { read } for  pid=1 comm="x" scontext=system_u:system_r:a_t:s0 tcontext=system_u:object_r:b_t:s0 tclass=file permissive=0`,
		`type=SELINUX_ERR msg=audit(1.0:1): op=something_else seresult=denied`,
	} {
		if _, err := ParseTransitionError(line); err == nil {
			t.Errorf("expected rejection for %q", line)
		}
	}
}

// The log scanner must surface both record types from one pass.
func TestParseLogFindsTransitionErrors(t *testing.T) {
	log := `type=AVC msg=audit(1.0:1): avc:  denied  { read } for  pid=1 comm="x" name="f" scontext=system_u:system_r:splunkuf_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0
type=SELINUX_ERR msg=audit(1.0:2): op=security_bounded_transition seresult=denied oldcontext=system_u:system_r:init_t:s0 newcontext=system_u:system_r:splunkuf_t:s0
`
	if ds := ParseLog(log); len(ds) != 1 {
		t.Errorf("want 1 AVC denial, got %d", len(ds))
	}
	errs := ParseTransitionErrors(log)
	if len(errs) != 1 || errs[0].NewType != "splunkuf_t" {
		t.Errorf("want 1 transition error for splunkuf_t, got %+v", errs)
	}
}
