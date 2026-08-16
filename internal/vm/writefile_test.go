package vm

import (
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

// Paths with shell metacharacters must be single-quoted safely.
func TestWriteFileScriptQuotesPath(t *testing.T) {
	if got, want := ShellQuote(`it's a $path`), `'it'\''s a $path'`; got != want {
		t.Errorf("ShellQuote = %q, want %q", got, want)
	}
	script := writeFileScript("/etc/app/x", "x")
	if !strings.Contains(script, `'/etc/app/x'`) {
		t.Errorf("path not single-quoted:\n%s", script)
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
