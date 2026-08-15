package vm

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

// SSH runs verifier scripts on a remote host over ssh — any RHEL-family
// machine with SELinux enforcing and passwordless sudo works: a lab box, a
// KVM guest, or an ephemeral EC2 instance created per pipeline run. This is
// the runner CI uses when the build host cannot nest virtualization.
type SSH struct {
	Target  string // user@host
	KeyPath string // optional identity file
	Timeout time.Duration
}

func (s *SSH) sshArgs(script string) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=15",
	}
	if s.KeyPath != "" {
		args = append(args, "-i", s.KeyPath)
	}
	args = append(args, s.Target, "bash", "-c", script)
	return args
}

func (s *SSH) Run(script string) (string, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	cmd := exec.Command("ssh", s.sshArgs(script)...)
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
		return string(out), fmt.Errorf("ssh timeout after %s", timeout)
	}
	if err != nil {
		return string(out), fmt.Errorf("remote script failed: %w\n%s", err, string(out))
	}
	return string(out), nil
}

func (s *SSH) WriteFile(path, content string) error {
	_, err := s.Run(writeFileScript(path, content))
	return err
}

// writeFileScript renders the remote write with a quoted heredoc so content
// passes through verbatim — no expansion of $vars or backticks server-side.
func writeFileScript(path, content string) string {
	return fmt.Sprintf("sudo mkdir -p %q && sudo tee %q > /dev/null <<'HARDENER_EOF'\n%s\nHARDENER_EOF",
		filepath.Dir(path), path, content)
}
