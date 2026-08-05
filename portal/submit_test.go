package portal

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gnolang/gno/tm2/pkg/crypto"

	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/clamav"
	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/scoring"
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

func (s *fakeStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.saved, key)
	return nil
}

type fakeLog struct {
	mu      sync.Mutex
	entries []Entry
}

func (l *fakeLog) Record(ctx context.Context, e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	return nil
}

type fakeScanner struct {
	verdict clamav.Verdict
	err     error
}

func (f fakeScanner) Scan(ctx context.Context, r io.Reader) (clamav.Verdict, error) {
	_, _ = io.Copy(io.Discard, r) // a real Scanner always drains r; assert callers behave the same
	return f.verdict, f.err
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

func TestSubmitHandler_StoresOriginalBytesAfterCleanScan(t *testing.T) {
	// TestSubmitHandler_Success leaves AVScanner nil, so nothing there
	// covers the scan-then-store sequence: the scanner drains the upload,
	// and only the Seek(0) that follows makes Store.Save see the archive
	// rather than zero bytes. Without this test, dropping that rewind
	// would silently store empty files with the suite still green.
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		AVScanner: fakeScanner{}, // clean verdict, no error
	}
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

	saved, ok := store.get(filename)
	if !ok {
		t.Fatal("archive was not stored")
	}
	if !bytes.Equal(saved, archive) {
		t.Errorf("stored %d bytes, want the %d uploaded bytes unchanged", len(saved), len(archive))
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

func TestSubmitHandler_RecordsLogOnSuccess(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	submissionLog := &fakeLog{}
	handler := &SubmitHandler{Sessions: sessions, Store: store, Log: submissionLog}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	if len(submissionLog.entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(submissionLog.entries))
	}
	got := submissionLog.entries[0]
	if got.Moniker != "samourai" || got.OperatorAddress != operatorAddr.String() || got.Filename != filename {
		t.Errorf("logged entry = %+v, unexpected content", got)
	}
}

func TestSubmitHandler_DoesNotRecordLogOnFailure(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	submissionLog := &fakeLog{}
	handler := &SubmitHandler{Sessions: sessions, Store: store, Log: submissionLog}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	// Bad filename -> ValidateFilename fails before Store.Save/Log.Record.
	body, contentType := multipartUpload(t, "not-the-right-convention.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	if len(submissionLog.entries) != 0 {
		t.Errorf("expected no logged entries on failure, got %+v", submissionLog.entries)
	}
}

func TestSubmitHandler_RejectsInfectedArchive(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		AVScanner: fakeScanner{verdict: clamav.Verdict{Infected: true, Signature: "Test-Signature"}},
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	if len(store.saved) != 0 {
		t.Error("infected archive should not have been stored")
	}
}

func TestSubmitHandler_RejectsWhenAVScannerUnavailable(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		AVScanner: fakeScanner{err: errors.New("connection refused")},
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail-closed on scanner unavailability)", resp.StatusCode)
	}
	if len(store.saved) != 0 {
		t.Error("archive should not have been stored when the AV scan could not run")
	}
}

func TestSubmitHandler_RecordsScoreWhenExerciseConfigured(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	submissionLog := &fakeLog{}

	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	cfg := exercise.Config{
		// A 4h announce-to-deadline window with AnnouncedAt just a
		// minute in the past keeps "submit now" well inside the first
		// quarter (the first hour), regardless of how long the test
		// itself takes to run — see scoring.TieredTimeScore.
		AnnouncedAt:              time.Now().UTC().Add(-time.Minute),
		DeadlineAt:               time.Now().UTC().Add(4 * time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
		ExpectedGenesisSHA256:    "deadbeef",
		SupportedGnolandVersions: []string{"v1.0.0"},
	}
	if err := exerciseStore.Set(cfg); err != nil {
		t.Fatalf("exerciseStore.Set: %v", err)
	}
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

	handler := &SubmitHandler{
		Sessions: sessions,
		Store:    store,
		Log:      submissionLog,
		Exercise: exerciseStore,
		Scores:   scoresStore,
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	submissionLog.mu.Lock()
	id := submissionLog.entries[0].ID
	submissionLog.mu.Unlock()
	if id == "" {
		t.Fatal("recorded entry has no ID")
	}

	result, ok, err := scoresStore.Get(id)
	if err != nil {
		t.Fatalf("scoresStore.Get: %v", err)
	}
	if !ok || !result.Scored {
		t.Fatalf("result = %+v, ok=%v, want a Scored result", result, ok)
	}
	if result.MetadataScore != 25 {
		t.Errorf("MetadataScore = %d, want 25", result.MetadataScore)
	}
	if result.UploadTimeScore != 25 {
		t.Errorf("UploadTimeScore = %d, want 25 (submitted well within the first quarter)", result.UploadTimeScore)
	}
}

func TestSubmitHandler_ScoresPendingWhenExerciseNotConfigured(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	submissionLog := &fakeLog{}

	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json")) // never Set
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

	handler := &SubmitHandler{
		Sessions: sessions,
		Store:    store,
		Log:      submissionLog,
		Exercise: exerciseStore,
		Scores:   scoresStore,
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (an unconfigured exercise must not block submission)", resp.StatusCode)
	}

	submissionLog.mu.Lock()
	id := submissionLog.entries[0].ID
	submissionLog.mu.Unlock()

	result, ok, err := scoresStore.Get(id)
	if err != nil {
		t.Fatalf("scoresStore.Get: %v", err)
	}
	if !ok {
		t.Fatal("expected a placeholder scoring record even with no exercise configured")
	}
	if result.Scored {
		t.Error("Scored = true, want false when the exercise wasn't configured at submit time")
	}
}
