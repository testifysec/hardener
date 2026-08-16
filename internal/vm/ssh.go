package vm

import (
	"context"
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
	// A Target beginning with '-' is parsed by ssh as an option, so a value like
	// "-oProxyCommand=<cmd>" would execute a local command instead of connecting
	// (review finding). ssh's own `--` handling is version-dependent, so reject
	// option-like targets outright — a real user@host never starts with '-'.
	if s.Target == "" || strings.HasPrefix(s.Target, "-") {
		return "", fmt.Errorf("invalid ssh target %q: must be user@host, not an option", s.Target)
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	// CommandContext kills the process on deadline itself — the previous manual
	// goroutine + cmd.Process.Kill() panicked when the timeout fired before
	// CombinedOutput started the process (Process still nil), e.g. with a small
	// timeout (review finding).
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", s.sshArgs()...)
	cmd.Stdin = strings.NewReader(script)
	out, over, err := runCapped(cmd)
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("ssh timeout after %s", timeout)
	}
	if over {
		return out, fmt.Errorf("remote script produced more than %d bytes of output — refusing a truncated result: %w", MaxOutputBytes, errOutputTooLarge)
	}
	if err != nil {
		return out, fmt.Errorf("remote script failed: %w\n%s", err, out)
	}
	return out, nil
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
