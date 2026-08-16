// Package vm runs commands inside the SELinux verifier VM.
package vm

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

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
	out, err := exec.CommandContext(ctx, "limactl", "shell", l.Instance, "--", "bash", "-c", script).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("timeout after %s", timeout)
	}
	if err != nil {
		return string(out), fmt.Errorf("vm script failed: %w\n%s", err, string(out))
	}
	return string(out), nil
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
