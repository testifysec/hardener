package vm

import (
	"encoding/base64"
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

// writeFileScript renders the remote write as base64 over the command, decoded
// to the target with tee. A fixed heredoc delimiter was unsafe: content
// containing a line equal to the delimiter would terminate it early and run
// the remainder as shell — with passwordless sudo (review finding). base64's
// alphabet has no shell metacharacters, so embedding it is safe; paths are
// single-quoted with ShellQuote (no Go %q expansion hazards).
func writeFileScript(path, content string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	return fmt.Sprintf("sudo mkdir -p %s && printf %%s %s | base64 -d | sudo tee %s > /dev/null",
		ShellQuote(filepath.Dir(path)), b64, ShellQuote(path))
}

// ShellQuote single-quotes s for POSIX shells. An embedded single quote is
// rendered as '\” — close the quote, an escaped literal quote, reopen.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
