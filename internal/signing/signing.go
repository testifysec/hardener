// Package signing provides optional, self-contained DSSE signing for verdict
// statements: an ed25519 key in PKCS#8 PEM, the DSSE pre-authentication
// encoding, and nothing else. No key generation, no keyless flows, no
// timestamps — for Fulcio keyless signing, RFC 3161 timestamps, and platform
// storage, wrap the run with CI/Lock instead:
//
//	cilock run --step confine -- hardener run ...
//
// Signing here exists so a factory with plain keys can gate deployments on
// the verdict without any additional tooling.
package signing

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// Envelope is a DSSE envelope (https://github.com/secure-systems-lab/dsse).
type Envelope struct {
	Payload     string      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// SignFile signs payload with the ed25519 private key at keyPath.
func SignFile(keyPath, payloadType string, payload []byte) (*Envelope, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM data", keyPath)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: parse PKCS#8 key: %w", keyPath, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: only ed25519 keys are supported (got %T); for other key types wrap with cilock", keyPath, parsed)
	}

	sig, err := priv.Sign(rand.Reader, pae(payloadType, payload), crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	keyID, err := keyIDOf(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: payloadType,
		Signatures:  []Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// pae computes the DSSE pre-authentication encoding:
// "DSSEv1" SP len(type) SP type SP len(body) SP body
func pae(payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

// keyIDOf is the sha256 of the PKIX DER encoding of the public key.
func keyIDOf(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
