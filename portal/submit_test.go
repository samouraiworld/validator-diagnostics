package portal

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gnolang/gno/tm2/pkg/crypto"

	"github.com/samourai/validator-diagnostics/auth"
)

// fakeStore is an in-memory storage.Store, so these tests don't need
// real object storage credentials — storage.S3Store's wire behavior is
// already covered separately in storage/s3_test.go.
type fakeStore struct {
	mu    sync.Mutex
	saved map[string][]byte
}

func newFakeStore() *fakeStore {
	return &fakeStore{saved: make(map[string][]byte)}
}

func (s *fakeStore) Save(ctx context.Context, key string, body io.Reader, size int64) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved[key] = data
	return nil
}

func (s *fakeStore) get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.saved[key]
	return data, ok
}

func buildValidArchive(t *testing.T, validatorAddress string) []byte {
	t.Helper()

	metadata := []byte(`{
		"validator_address": "` + validatorAddress + `",
		"moniker": "samourai",
		"chain_id": "topaz-1",
		"gnoland_version": "v1.0.0",
		"genesis_sha256": "deadbeef",
		"operating_system": "Debian 12",
		"architecture": "amd64",
		"sentry_enabled": true,
		"backup_node": true,
		"hosting_provider": "Scaleway",
		"deployment_method": "docker",
		"recent_operations": "None"
	}`)
	logContent := append([]byte{0x1f, 0x8b}, []byte("fake gzip log payload")...)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, e := range []struct {
		name    string
		content []byte
	}{
		{"gnoland.log.gz", logContent},
		{"metadata.json", metadata},
	} {
		hdr := &tar.Header{Name: e.name, Typeflag: tar.TypeReg, Size: int64(len(e.content)), Mode: 0o644}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write(e.content); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	return buf.Bytes()
}

// multipartUpload builds a POST body with the archive under the
// "archive" field, named filename.
func multipartUpload(t *testing.T, filename string, content []byte) (body *bytes.Buffer, contentType string) {
	t.Helper()

	body = &bytes.Buffer{}
	mw := multipart.NewWriter(body)

	part, err := mw.CreateFormFile("archive", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart Close: %v", err)
	}

	return body, mw.FormDataContentType()
}

func testOperatorAddr() crypto.Address {
	var addr crypto.Address
	copy(addr[:], []byte("01234567890123456789")) // 20 bytes
	return addr
}

func TestSubmitHandler_Success(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()

	handler := &SubmitHandler{Sessions: sessions, Store: store}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	filename := "samourai-20260709-1830UTC.tar.gz"
	body, contentType := multipartUpload(t, filename, archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	var result submitResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !result.OK {
		t.Fatalf("submit failed: status=%d ok=%v err=%q", resp.StatusCode, result.OK, result.Error)
	}
	if result.Moniker != "samourai" {
		t.Errorf("Moniker = %q, want %q", result.Moniker, "samourai")
	}

	saved, ok := store.get(filename)
	if !ok {
		t.Fatal("archive was not stored")
	}
	if !bytes.Equal(saved, archive) {
		t.Error("stored bytes do not match the uploaded archive")
	}
}

func TestSubmitHandler_RejectsMissingSession(t *testing.T) {
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	store := newFakeStore()
	handler := &SubmitHandler{Sessions: sessions, Store: store}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, testOperatorAddr().String())
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	// No Authorization header.

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if len(store.saved) != 0 {
		t.Error("archive should not have been stored")
	}
}

func TestSubmitHandler_RejectsIdentityMismatch(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	handler := &SubmitHandler{Sessions: sessions, Store: store}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// metadata.json claims a *different* validator_address than the
	// one the session token authenticated.
	archive := buildValidArchive(t, "g1someoneelse00000000000000000000000000")
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if len(store.saved) != 0 {
		t.Error("archive should not have been stored")
	}
}

func TestSubmitHandler_RejectsBadFilename(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	handler := &SubmitHandler{Sessions: sessions, Store: store}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	body, contentType := multipartUpload(t, "not-the-right-convention.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if len(store.saved) != 0 {
		t.Error("archive should not have been stored")
	}
}

func TestSubmitHandler_RejectsMalformedArchive(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	handler := &SubmitHandler{Sessions: sessions, Store: store}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", []byte("not a tar.gz at all"))

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if len(store.saved) != 0 {
		t.Error("archive should not have been stored")
	}
}
