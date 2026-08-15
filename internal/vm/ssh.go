package vm

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
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

// sshArgs builds the ssh invocation. The remote command is a fixed `bash -s`;
// the script is delivered on stdin (see Run) so ssh never word-splits a
// multi-line script — OpenSSH concatenates trailing args with spaces, which
// would turn `bash -c <loop\nheredoc>` into `bash -c <first-word>` and reparse
// the rest in the remote shell.
func (s *SSH) sshArgs() []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=15",
	}
	if s.KeyPath != "" {
		args = append(args, "-i", s.KeyPath)
	}
	args = append(args, s.Target, "bash", "-s")
	return args
}

func (s *SSH) Run(script string) (string, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	cmd := exec.Command("ssh", s.sshArgs()...)
	cmd.Stdin = strings.NewReader(script)
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
