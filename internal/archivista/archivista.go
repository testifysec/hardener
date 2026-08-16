// Package archivista uploads signed verdict envelopes to an Archivista
// attestation store. Strictly optional: no --archivista-url, no upload, no
// network. The factory's own store, the hosted platform, or nothing at all —
// the operator decides.
package archivista

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/testifysec/hardener/internal/signing"
)

// Upload POSTs a DSSE envelope to {base}/upload and returns the gitoid.
func Upload(baseURL string, env *signing.Envelope) (string, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	url := strings.TrimSuffix(baseURL, "/") + "/upload"
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("archivista upload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("archivista upload: %s returned %s", url, resp.Status)
	}
	var out struct {
		Gitoid string `json:"gitoid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("archivista upload: decode response: %w", err)
	}
	// A 200 with an empty gitoid is NOT a successful store — Archivista returns
	// the object's gitoid on success, so an empty one means the evidence was not
	// persisted. Reporting it as stored would falsely claim the attestation is
	// retrievable (review finding).
	if strings.TrimSpace(out.Gitoid) == "" {
		return "", fmt.Errorf("archivista upload: %s returned 200 with no gitoid — evidence was not stored", url)
	}
	return out.Gitoid, nil
}
