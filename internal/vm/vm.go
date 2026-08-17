// Package vm runs commands inside the SELinux verifier VM.
package vm

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// MaxOutputBytes bounds how much combined output one remote script may buffer.
// Scripts are manifest-controlled, so an unbounded CombinedOutput let a target
// exhaust the runner's memory before the timeout ever fired (review finding —
// round 74).
//
// On overflow we FAIL rather than truncate. Truncating to a diagnostic tail (the
// suggested remedy) would be unsafe here: callers PARSE this output — most
// critically the audit-log window, whose AVC records sit at the START of the
// slice. Silently dropping the beginning would turn a denied run into a clean
// one. A hard error keeps memory bounded without ever handing a caller a partial
// slice it would mistake for complete.
const MaxOutputBytes = 64 << 20 // 64 MiB

// cappedWriter accumulates output up to limit, then refuses further writes and
// invokes onOver so the command can be torn down. It keeps what it captured for
// diagnostics.
type cappedWriter struct {
	buf    strings.Builder
	limit  int
	over   bool
	onOver func() // called once, when the limit is first exceeded
}

var errOutputTooLarge = fmt.Errorf("script output exceeded %d bytes", MaxOutputBytes)

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.over {
		return 0, errOutputTooLarge
	}
	if w.buf.Len()+len(p) > w.limit {
		if room := w.limit - w.buf.Len(); room > 0 {
			w.buf.Write(p[:room])
		}
		w.over = true
		// Returning an error stops the copy goroutine but does NOT stop the child:
		// a process emitting continuous output would then block on a full pipe until
		// the 10-minute timeout, holding the runner for no reason (review finding —
		// round 75). Kill it now.
		if w.onOver != nil {
			w.onOver()
		}
		return 0, errOutputTooLarge
	}
	return w.buf.Write(p)
}

// runCapped runs cmd with both streams captured into a size-limited buffer,
// killing the child as soon as the limit is exceeded. Returns the captured
// output, whether the limit was hit, and the run error.
func runCapped(cmd *exec.Cmd) (string, bool, error) {
	return runCappedLimit(cmd, MaxOutputBytes)
}

// runCappedLimit is runCapped with an explicit limit so tests can exercise the
// overflow path — including the kill wiring — through the SAME code the
// production path uses. A test that rebuilt the callback itself would stay green
// if that wiring were removed here (review finding — round 77).
func runCappedLimit(cmd *exec.Cmd, limit int) (string, bool, error) {
	w := &cappedWriter{limit: limit}
	w.onOver = func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	cmd.Stdout = w
	cmd.Stderr = w
	err := cmd.Run()
	return w.buf.String(), w.over, err
}

// Runner executes scripts in the verifier environment.
type Runner interface {
	// Run executes a bash script and returns combined output.
	Run(script string) (string, error)
	// WriteFile places content at path inside the VM (via sudo tee).
	WriteFile(path, content string) error
}

// Lima runs scripts in a Lima instance.
type Lima struct {
	Instance string
	Timeout  time.Duration
	Verbose  func(stage, out string)
}

func (l *Lima) Run(script string) (string, error) {
	// An instance name beginning with '-' is parsed by `limactl shell` as a flag
	// (e.g. "--help"), which can exit 0 WITHOUT running the script and make Run/
	// WriteFile report false success (review finding). Reject empty or option-
	// like instance names — a real Lima instance name never starts with '-'.
	if l.Instance == "" || strings.HasPrefix(l.Instance, "-") {
		return "", fmt.Errorf("invalid lima instance %q: must be an instance name, not an option", l.Instance)
	}
	timeout := l.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	// CommandContext handles the kill on timeout itself — the previous manual
	// goroutine + cmd.Process.Kill() panicked when the deadline fired before
	// CombinedOutput had started the process (Process still nil), especially
	// with a small timeout (review finding).
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, over, err := runCapped(exec.CommandContext(ctx, "limactl", "shell", l.Instance, "--", "bash", "-c", script))
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("timeout after %s", timeout)
	}
	if over {
		return out, fmt.Errorf("vm script produced more than %d bytes of output — refusing a truncated result: %w", MaxOutputBytes, errOutputTooLarge)
	}
	if err != nil {
		return out, fmt.Errorf("vm script failed: %w\n%s", err, out)
	}
	return out, nil
}

func (l *Lima) WriteFile(path, content string) error {
	_, err := l.Run(writeFileScript(path, content))
	return err
}

func dirOf(path string) string {
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "/"
	}
	return path[:i]
}
