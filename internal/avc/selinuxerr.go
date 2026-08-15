package avc

import (
	"errors"
	"strings"
)

// TransitionError is a SELINUX_ERR record reporting a refused domain
// transition. The common cause is a systemd unit with NoNewPrivileges=yes:
// the kernel then permits only a *bounded* transition (the new domain must be
// a subset of the old one), which a generated application domain is not.
// No amount of allow-rule refinement can fix it — the unit must change, or the
// domain must be declared with typebounds.
type TransitionError struct {
	Op      string
	OldType string
	NewType string
}

// ParseTransitionError parses one SELINUX_ERR transition record.
func ParseTransitionError(line string) (*TransitionError, error) {
	if !strings.Contains(line, "type=SELINUX_ERR") || !strings.Contains(line, "transition") {
		return nil, errors.New("not a transition error record")
	}
	e := &TransitionError{}
	for _, f := range fieldRe.FindAllStringSubmatch(line, -1) {
		key, val := f[1], strings.Trim(f[2], `"`)
		switch key {
		case "op":
			e.Op = val
		case "oldcontext":
			e.OldType = contextType(val)
		case "newcontext":
			e.NewType = contextType(val)
		}
	}
	if e.NewType == "" {
		return nil, errors.New("transition record missing contexts")
	}
	return e, nil
}

// ParseTransitionErrors extracts every refused transition from a log blob.
func ParseTransitionErrors(log string) []TransitionError {
	var out []TransitionError
	for _, line := range strings.Split(log, "\n") {
		if e, err := ParseTransitionError(line); err == nil {
			out = append(out, *e)
		}
	}
	return out
}
