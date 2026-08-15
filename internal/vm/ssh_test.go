package vm

import (
	"strings"
	"testing"
)

func TestSSHArgConstruction(t *testing.T) {
	s := &SSH{Target: "ec2-user@10.0.0.5", KeyPath: "/keys/verifier.pem"}
	args := s.sshArgs("getenforce")
	joined := strings.Join(args, " ")
	for _, want := range []string{"-o BatchMode=yes", "-i /keys/verifier.pem", "ec2-user@10.0.0.5"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	// the script must be the final argument, passed to bash -c remotely
	if args[len(args)-1] != "getenforce" {
		t.Errorf("script must be last arg: %v", args)
	}
	if args[len(args)-2] != "bash -c" && args[len(args)-3] != "bash" {
		// remote command is: bash -c <script>
		found := false
		for i, a := range args {
			if a == "bash" && i+2 < len(args) && args[i+1] == "-c" {
				found = true
			}
		}
		if !found {
			t.Errorf("remote command must be bash -c <script>: %v", args)
		}
	}
}

func TestSSHNoKeyOmitsIdentity(t *testing.T) {
	s := &SSH{Target: "user@host"}
	joined := strings.Join(s.sshArgs("true"), " ")
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
