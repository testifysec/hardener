package vm

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Content containing the old fixed heredoc delimiter must NOT be able to
// terminate the transport early and run the remainder as shell (these
// verifiers have passwordless sudo). Transport is base64 over stdin.
func TestWriteFileScriptResistsDelimiterInjection(t *testing.T) {
	evil := "line one\nHARDENER_EOF\nrm -rf /\n"
	script := writeFileScript("/etc/app/conf", evil)
	if strings.Contains(script, "rm -rf /") {
		t.Errorf("raw content leaked into the script (heredoc injection):\n%s", script)
	}
	if strings.Contains(script, "HARDENER_EOF") {
		t.Errorf("no fixed heredoc delimiter may appear:\n%s", script)
	}
	if !strings.Contains(script, "base64 -d") || !strings.Contains(script, "tee") {
		t.Errorf("expected base64 -d | tee transport:\n%s", script)
	}
}

// Paths with shell metacharacters must be single-quoted safely. Route the
// metacharacter path THROUGH writeFileScript and assert its ShellQuote'd form
// appears — testing ShellQuote in isolation and then calling writeFileScript with
// a safe path would still pass if writeFileScript stopped quoting the path at all
// (review finding — round 65).
func TestWriteFileScriptQuotesPath(t *testing.T) {
	evilPath := `/etc/app/it's $(touch pwn)`
	script := writeFileScript(evilPath, "x")
	// The fully escaped form must be present verbatim...
	if want := ShellQuote(evilPath); !strings.Contains(script, want) {
		t.Errorf("writeFileScript did not route the path through ShellQuote; want %q in:\n%s", want, script)
	}
	// ...and the raw, unescaped sequence must NOT appear: ShellQuote breaks the
	// apostrophe with '\'' , so a correctly-quoted script never contains the bare
	// `it's $(touch pwn)` run. Its presence means the path went in unquoted.
	if strings.Contains(script, `it's $(touch pwn)`) {
		t.Errorf("raw unescaped path leaked into the sudo'd script:\n%s", script)
	}
}

// Round 23: a tiny/expired timeout must return an error, never panic — the old
// manual goroutine + cmd.Process.Kill() panicked when the deadline fired before
// the process started (Process still nil).
func TestSSHTinyTimeoutNoPanic(t *testing.T) {
	s := &SSH{Target: "nobody@203.0.113.1", Timeout: time.Nanosecond}
	if _, err := s.Run("echo hi"); err == nil {
		t.Error("a 1ns timeout (or missing ssh) must return an error, not succeed")
	}
}

// Round 25/26: an option-like Target/Instance must be rejected before it can be
// parsed by ssh/limactl as a flag (-oProxyCommand=… local exec, or --help that
// exits 0 without running the script — a false success).
func TestSSHRejectsOptionLikeTarget(t *testing.T) {
	for _, tgt := range []string{"", "-oProxyCommand=touch /tmp/pwn", "--help"} {
		s := &SSH{Target: tgt}
		if _, err := s.Run("echo hi"); err == nil {
			t.Errorf("option-like ssh target %q must be rejected", tgt)
		}
	}
}

func TestLimaRejectsOptionLikeInstance(t *testing.T) {
	for _, inst := range []string{"", "--help", "-f"} {
		l := &Lima{Instance: inst}
		if _, err := l.Run("echo hi"); err == nil {
			t.Errorf("option-like lima instance %q must be rejected", inst)
		}
	}
}

// Round 74: script output is manifest-controlled, so an unbounded CombinedOutput
// let a target exhaust the runner's memory before the timeout fired. The buffer is
// now capped — and on overflow we FAIL rather than truncate: callers PARSE this
// output, most critically the audit window whose AVC records sit at the START of
// the slice, so silently dropping the beginning would turn a denied run clean.
func TestCappedWriterBoundsOutputAndFailsClosed(t *testing.T) {
	w := &cappedWriter{limit: 100}
	if n, err := w.Write([]byte(strings.Repeat("a", 60))); err != nil || n != 60 {
		t.Fatalf("write under the limit must succeed, got n=%d err=%v", n, err)
	}
	if w.over {
		t.Fatal("writer must not be marked over before the limit is exceeded")
	}
	// Crossing the limit must report an error (so the command is torn down) and
	// latch `over` — never silently accept and drop data.
	if _, err := w.Write([]byte(strings.Repeat("b", 60))); err == nil {
		t.Error("a write crossing the limit must return an error")
	}
	if !w.over {
		t.Error("the writer must latch over=true once the limit is exceeded")
	}
	if w.buf.Len() > w.limit {
		t.Errorf("buffered %d bytes, must never exceed the limit %d", w.buf.Len(), w.limit)
	}
	// Subsequent writes keep failing rather than resuming.
	if _, err := w.Write([]byte("c")); err == nil {
		t.Error("writes after the limit must keep failing")
	}
}

// Round 75: returning an error from the capped writer stops the copy goroutine but
// does NOT stop the child — a process emitting continuous output would block on a
// full pipe until the 10-minute timeout. The writer must kill the command as soon
// as the cap is exceeded.
func TestRunCappedKillsChildOnOverflow(t *testing.T) {
	// yes(1) emits unbounded output; with a tiny cap this must return promptly
	// rather than hang until a timeout.
	cmd := exec.Command("sh", "-c", "yes hello")
	w := &cappedWriter{limit: 4096}
	w.onOver = func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	cmd.Stdout = w
	cmd.Stderr = w
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- cmd.Run() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("runCapped must kill the child on overflow, not block until the timeout")
	}
	if !w.over {
		t.Error("the writer must have latched over=true")
	}
	if w.buf.Len() > w.limit {
		t.Errorf("buffered %d bytes, must not exceed the cap %d", w.buf.Len(), w.limit)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("took %s — the child was not killed promptly", elapsed)
	}
}
