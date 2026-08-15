// Package vm runs commands inside the SELinux verifier VM.
package vm

import (
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
	cmd := exec.Command("limactl", "shell", l.Instance, "--", "bash", "-c", script)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return string(out), fmt.Errorf("timeout after %s", timeout)
	}
	if err != nil {
		return string(out), fmt.Errorf("vm script failed: %w\n%s", err, string(out))
	}
	return string(out), nil
}

func (l *Lima) WriteFile(path, content string) error {
	script := fmt.Sprintf("sudo mkdir -p %q && sudo tee %q > /dev/null <<'HARDENER_EOF'\n%s\nHARDENER_EOF",
		dirOf(path), path, content)
	_, err := l.Run(script)
	return err
}

func dirOf(path string) string {
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "/"
	}
	return path[:i]
}
