package vm

import (
	"strings"
	"testing"
)

func TestSSHArgConstruction(t *testing.T) {
	s := &SSH{Target: "ec2-user@10.0.0.5", KeyPath: "/keys/verifier.pem"}
	args := s.sshArgs()
	joined := strings.Join(args, " ")
	for _, want := range []string{"-o BatchMode=yes", "-i /keys/verifier.pem", "ec2-user@10.0.0.5"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	// The remote command must be `bash -s` — the script arrives on stdin, so a
	// multi-line script with loops and heredocs is preserved verbatim rather
	// than word-split by ssh's argument concatenation.
	if args[len(args)-2] != "bash" || args[len(args)-1] != "-s" {
		t.Errorf("remote command must be `bash -s`: %v", args)
	}
	// The target must precede the remote command.
	ti, bi := -1, -1
	for i, a := range args {
		if a == "ec2-user@10.0.0.5" {
			ti = i
		}
		if a == "bash" {
			bi = i
		}
	}
	if ti < 0 || bi < ti {
		t.Errorf("target must come before the remote command: %v", args)
	}
}

func TestSSHNoKeyOmitsIdentity(t *testing.T) {
	s := &SSH{Target: "user@host"}
	joined := strings.Join(s.sshArgs(), " ")
	if strings.Contains(joined, "-i ") {
		t.Errorf("no key configured, -i must be absent: %s", joined)
	}
}

// WriteFile must heredoc-quote content so the remote shell never interprets it.
func TestSSHWriteFileScriptShape(t *testing.T) {
	script := writeFileScript("/etc/app/conf", "line with $VAR and `backticks`\n")
	if !strings.Contains(script, "<<'HARDENER_EOF'") {
		t.Errorf("heredoc must be quoted (no expansion): %s", script)
	}
	if !strings.Contains(script, "$VAR") || !strings.Contains(script, "`backticks`") {
		t.Errorf("content must pass through verbatim: %s", script)
	}
	if !strings.Contains(script, `sudo mkdir -p "/etc/app"`) {
		t.Errorf("parent dir must be created: %s", script)
	}
}
