package verdict

import (
	"encoding/json"
	"strings"
	"testing"
)

const goodSHA = "abababababababababababababababababababababababababababababababab"

// A malformed or empty subject digest must fail statement construction — an
// attestation whose subject digest is garbage binds to nothing (review finding).
func TestBuildRejectsMalformedDigest(t *testing.T) {
	r := passingResult()
	_, err := BuildOrErr(r, Env{}, []Subject{{Name: "app.rpm", SHA256: "ab12"}})
	if err == nil {
		t.Fatal("short/malformed digest must be rejected")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("error should name the digest problem: %v", err)
	}
}

// A run that produced a policy RPM must carry it as a subject with a valid digest.
func TestBuildRequiresAValidSubject(t *testing.T) {
	r := passingResult()
	st, err := BuildOrErr(r, Env{}, []Subject{{Name: "app-selinux.rpm", SHA256: goodSHA}})
	if err != nil {
		t.Fatalf("valid digest must be accepted: %v", err)
	}
	// Every subject digest in the statement must be 64-hex.
	for _, s := range st.Subject {
		d := s.Digest["sha256"]
		if len(d) != 64 {
			t.Errorf("subject %s has non-64-hex digest %q", s.Name, d)
		}
	}
	// At least one subject must exist (the policy RPM or the entrypoint bytes).
	if len(st.Subject) == 0 {
		t.Error("a PASS statement must bind to at least one artifact")
	}
}

// Entrypoint digests supplied by the pipeline become subjects, binding the
// verdict to the exact exercised bytes, not just the generated policy.
func TestBuildBindsEntrypointDigests(t *testing.T) {
	r := passingResult()
	r.EntrypointDigests = map[string]string{"/usr/sbin/widgetd": goodSHA}
	st, err := BuildOrErr(r, Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range st.Subject {
		if s.Name == "/usr/sbin/widgetd" && s.Digest["sha256"] == goodSHA {
			found = true
		}
	}
	if !found {
		t.Errorf("entrypoint bytes must be a subject: %+v", st.Subject)
	}
}

// A passing verdict must bind to the exercised artifact (RPM or entrypoint
// bytes), not merely to the generated policy text — otherwise a deploy gate
// trusts a claim tied to nothing it will actually install (review finding).
func TestPassingVerdictRequiresArtifactSubject(t *testing.T) {
	r := passingResult()
	r.RPMPath = ""
	r.EntrypointDigests = nil // only .te/.fc would remain
	if _, err := BuildOrErr(r, Env{}, nil); err == nil {
		t.Fatal("passing verdict with only policy-text subjects must be rejected")
	}
	// With an entrypoint digest it succeeds.
	r.EntrypointDigests = map[string]string{"/usr/sbin/widgetd": goodSHA}
	if _, err := BuildOrErr(r, Env{}, nil); err != nil {
		t.Fatalf("entrypoint-bound passing verdict must be accepted: %v", err)
	}
}

// Identical inputs must produce byte-identical statements — a map iteration
// over entrypoint digests would otherwise reorder subjects and change the
// DSSE signature (review finding).
func TestStatementIsDeterministic(t *testing.T) {
	r := passingResult()
	r.EntrypointDigests = map[string]string{
		"/usr/sbin/a": goodSHA, "/usr/sbin/b": goodSHA, "/usr/sbin/c": goodSHA,
		"/usr/sbin/d": goodSHA, "/usr/sbin/e": goodSHA,
	}
	var first []byte
	for i := 0; i < 20; i++ {
		st, err := BuildOrErr(r, Env{Mode: "Enforcing"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(st)
		if first == nil {
			first = raw
		} else if string(raw) != string(first) {
			t.Fatalf("statement bytes differ across builds (non-deterministic subject order)")
		}
	}
}
