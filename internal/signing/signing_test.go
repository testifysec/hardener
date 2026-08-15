package signing

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeTestKey(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

// PAE is the DSSE pre-authentication encoding; get it wrong and nothing
// interoperates. Golden vector from the DSSE spec.
func TestPAE(t *testing.T) {
	got := pae("http://example.com/HelloWorld", []byte("hello world"))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if string(got) != want {
		t.Errorf("PAE:\n got %q\nwant %q", got, want)
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	keyPath, pub := writeTestKey(t)
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicate":{"verdict":"pass"}}`)

	env, err := SignFile(keyPath, "application/vnd.in-toto+json", payload)
	if err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	if env.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("payloadType: %q", env.PayloadType)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID == "" {
		t.Fatalf("signatures: %+v", env.Signatures)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || string(body) != string(payload) {
		t.Fatalf("payload round-trip failed: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, pae(env.PayloadType, payload), sig) {
		t.Error("signature does not verify against the PAE of the payload")
	}
}

// The envelope must serialize to the DSSE wire format.
func TestEnvelopeWireFormat(t *testing.T) {
	keyPath, _ := writeTestKey(t)
	env, err := SignFile(keyPath, "t", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"payload", "payloadType", "signatures"} {
		if _, ok := m[k]; !ok {
			t.Errorf("wire format missing %q: %s", k, raw)
		}
	}
}

func TestRejectsNonEd25519AndGarbage(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(bad, []byte("not a key"), 0o600)
	if _, err := SignFile(bad, "t", []byte("x")); err == nil {
		t.Error("garbage key must be rejected")
	}
	if _, err := SignFile(filepath.Join(t.TempDir(), "missing.pem"), "t", []byte("x")); err == nil {
		t.Error("missing key must be rejected")
	}
}
