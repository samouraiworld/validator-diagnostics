package storage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestS3StoreSave drives a real PutObject call against a fake
// S3-compatible HTTP server (via BaseEndpoint), asserting the request
// method, path, and body the SDK actually sends — not just that the
// code compiles. This is how any S3-compatible provider (Scaleway, R2,
// MinIO) would see the request too, since they all speak the same wire
// protocol this test asserts against.
func TestS3StoreSave(t *testing.T) {
	const (
		bucket  = "validator-fire-drill"
		key     = "samourai-20260709-1830UTC.tar.gz"
		content = "fake archive bytes"
	)

	var (
		gotMethod string
		gotPath   string
		gotBody   string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		gotBody = string(body)

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store, err := NewS3Store(context.Background(), S3Config{
		Bucket:    bucket,
		Region:    "fr-par",
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
		Endpoint:  srv.URL,
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	err = store.Save(context.Background(), key, strings.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	wantPath := "/" + bucket + "/" + key
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotBody != content {
		t.Errorf("body = %q, want %q", gotBody, content)
	}
}

// TestS3StoreDelete asserts the request DeleteObject actually sends —
// method and path — against a fake S3-compatible server, same approach
// as TestS3StoreSave.
func TestS3StoreDelete(t *testing.T) {
	const (
		bucket = "validator-fire-drill"
		key    = "samourai-20260709-1830UTC.tar.gz"
	)

	var gotMethod, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	store, err := NewS3Store(context.Background(), S3Config{
		Bucket:    bucket,
		Region:    "fr-par",
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
		Endpoint:  srv.URL,
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	wantPath := "/" + bucket + "/" + key
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
}
