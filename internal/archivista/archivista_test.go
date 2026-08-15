package archivista

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/testifysec/hardener/internal/signing"
)

func TestUpload(t *testing.T) {
	var gotPath, gotType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"gitoid": "abc123"})
	}))
	defer srv.Close()

	env := &signing.Envelope{Payload: "eA==", PayloadType: "t", Signatures: []signing.Signature{{KeyID: "k", Sig: "cw=="}}}
	gitoid, err := Upload(srv.URL, env)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if gitoid != "abc123" {
		t.Errorf("gitoid: %q", gitoid)
	}
	if gotPath != "/upload" {
		t.Errorf("path: %q", gotPath)
	}
	if gotType != "application/json" {
		t.Errorf("content type: %q", gotType)
	}
	var round signing.Envelope
	if err := json.Unmarshal(gotBody, &round); err != nil || round.PayloadType != "t" {
		t.Errorf("body round-trip: %v %+v", err, round)
	}
}

func TestUploadServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 500)
	}))
	defer srv.Close()
	if _, err := Upload(srv.URL, &signing.Envelope{}); err == nil {
		t.Error("server error must surface")
	}
}

func TestUploadUnreachable(t *testing.T) {
	if _, err := Upload("http://127.0.0.1:1", &signing.Envelope{}); err == nil {
		t.Error("unreachable server must error")
	}
}
