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
	"github.com/samourai/validator-diagnostics/storage"
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

// buildValidArchive is buildArchiveWithLog carrying a genuinely
// decompressible gnoland.log.gz. The AV pass reads that stream now, so the
// hand-rolled two-magic-bytes stand-in this used to write would be rejected
// as an unreadable log rather than exercising the happy path.
func buildValidArchive(t *testing.T, validatorAddress string) []byte {
	t.Helper()
	return buildArchiveWithLog(t, validatorAddress, gzipBytes(t, []byte("fake gzip log payload")))
}

// buildArchiveWithLog builds the same archive with the gnoland.log.gz
// entry's raw bytes under the caller's control, so a test can supply a
// broken or truncated gzip.
func buildArchiveWithLog(t *testing.T, validatorAddress string, logContent []byte) []byte {
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

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, e := range []struct {
		name    string
		content []byte
	}{
		{"validator.log.gz", logContent},
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

func gzipBytes(t *testing.T, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(content); err != nil {
		t.Fatalf("gzip Write: %v", err)
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

// TestSubmitHandler_StoresViaRealS3StoreOverPlainHTTP is the regression test
// for the storing phase's progress wrapper. fakeStore accepts any io.Reader,
// so it never noticed that Store.Save was handed a reader that couldn't
// seek: every other test in this file stores through fakeStore and would
// stay green either way. storage.S3Store hands its body straight to the AWS
// SDK's PutObject, whose checksum middleware refuses a non-seekable stream
// over plain HTTP — exactly docker-compose.yml's configuration
// (-s3-endpoint=http://minio:9001) — so this drives a real *storage.S3Store
// against a plain-HTTP httptest server, the same fake-server pattern
// storage/s3_test.go uses, instead of a double. That is the only way to
// actually exercise the AWS SDK's seekability requirement rather than assert
// around it.
func TestSubmitHandler_StoresViaRealS3StoreOverPlainHTTP(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)

	var gotBody []byte
	fakeS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("fake S3 server: reading request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeS3.Close()

	store, err := storage.NewS3Store(context.Background(), storage.S3Config{
		Bucket:    "validator-fire-drill",
		Region:    "fr-par",
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
		Endpoint:  fakeS3.URL, // plain http://, deliberately: this is the configuration that breaks
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

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
		t.Fatalf("submit failed: status=%d ok=%v err=%q — this is the exact failure mode docker-compose.yml hits "+
			"(a plain-HTTP S3 endpoint) if the storing phase's wrapper around the multipart.File doesn't forward Seek",
			resp.StatusCode, result.OK, result.Error)
	}
	if !bytes.Equal(gotBody, archive) {
		t.Error("the fake S3 server did not receive the uploaded archive's exact bytes")
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

// submitArchive posts archive to a server wrapping handler and returns the
// response status. handler's Sessions must be sessions.
func submitArchive(t *testing.T, handler *SubmitHandler, sessions *auth.SessionSigner, addr crypto.Address, archive []byte) int {
	t.Helper()

	srv := httptest.NewServer(handler)
	defer srv.Close()

	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)
	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+sessions.Issue(addr))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// capturingScanner records every stream it is handed, so the tests can
// assert what clamd would actually have received.
type capturingScanner struct {
	mu       sync.Mutex
	streams  [][]byte
	verdicts []clamav.Verdict
	errs     []error
}

func (s *capturingScanner) Scan(ctx context.Context, r io.Reader) (clamav.Verdict, error) {
	data, err := io.ReadAll(r)
	s.mu.Lock()
	i := len(s.streams)
	s.streams = append(s.streams, data)
	s.mu.Unlock()
	if err != nil {
		return clamav.Verdict{}, err
	}
	if i < len(s.errs) && s.errs[i] != nil {
		return clamav.Verdict{}, s.errs[i]
	}
	if i < len(s.verdicts) {
		return s.verdicts[i], nil
	}
	return clamav.Verdict{}, nil
}

func (s *capturingScanner) captured() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams
}

func TestSubmitHandler_ScansExtractedContentNotTheArchive(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	scanner := &capturingScanner{}
	submissionLog := &fakeLog{}

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     newFakeStore(),
		Log:       submissionLog,
		AVScanner: scanner,
	}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	streams := scanner.captured()
	if len(streams) != 2 {
		t.Fatalf("got %d scans, want 2 (metadata.json, then the log)", len(streams))
	}
	if !bytes.Contains(streams[0], []byte(`"moniker": "samourai"`)) {
		t.Error("the first scan is not metadata.json")
	}
	if string(streams[1]) != "fake gzip log payload" {
		t.Errorf("the second scan is %q, want the decompressed log — clamd must never see compressed or archived bytes", streams[1])
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	got := submissionLog.entries[0].Scan
	if got == nil {
		t.Fatal("Entry.Scan = nil, want a coverage claim")
	}
	if !got.Complete || got.Bytes != int64(len("fake gzip log payload")) {
		t.Errorf("Scan = %+v, want complete coverage of the decompressed log", *got)
	}
}

func TestSubmitHandler_RejectsUnreadableLogGzip(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	store := newFakeStore()

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		AVScanner: &capturingScanner{},
	}

	// The right magic bytes over a header that is not a gzip header:
	// ValidateArchive accepts it, and nothing beyond it can ever be read.
	broken := append([]byte{0x1f, 0x8b}, []byte("not really a gzip header at all")...)
	archive := buildArchiveWithLog(t, operatorAddr.String(), broken)

	if status := submitArchive(t, handler, sessions, operatorAddr, archive); status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: a log nothing can read is a log nothing can scan", status)
	}
	if _, ok := store.get("samourai-20260709-1830UTC.tar.gz"); ok {
		t.Error("the archive was stored despite being entirely unscanned")
	}
}

func TestSubmitHandler_AcceptsTruncatedLogWithPartialCoverage(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	store := newFakeStore()
	submissionLog := &fakeLog{}

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		Log:       submissionLog,
		AVScanner: &capturingScanner{},
	}

	// A real gzip stream with its tail cut off — a full disk or a killed
	// collection process, not an exotic case. The exercise wants the
	// diagnostic it can still read.
	full := gzipBytes(t, []byte("a log that was being written when the disk filled up"))
	archive := buildArchiveWithLog(t, operatorAddr.String(), full[:len(full)-8])

	if status := submitArchive(t, handler, sessions, operatorAddr, archive); status != http.StatusOK {
		t.Fatalf("status = %d, want 200: what could be read was read", status)
	}
	if _, ok := store.get("samourai-20260709-1830UTC.tar.gz"); !ok {
		t.Error("the archive was not stored")
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	got := submissionLog.entries[0].Scan
	if got == nil {
		t.Fatal("Entry.Scan = nil, want a partial coverage claim")
	}
	if got.Complete {
		t.Error("Complete = true, want false: the stream broke before the end")
	}
}

func TestSubmitHandler_NoScannerMakesNoClaim(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	submissionLog := &fakeLog{}

	handler := &SubmitHandler{
		Sessions: sessions,
		Store:    newFakeStore(),
		Log:      submissionLog,
		// AVScanner deliberately nil — cmd/portal-dev runs this way.
	}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	if submissionLog.entries[0].Scan != nil {
		t.Errorf("Scan = %+v, want nil: nothing examined this submission, so nothing may vouch for it",
			*submissionLog.entries[0].Scan)
	}
}

func TestSubmitHandler_BudgetExhaustedIsRecordedNotRejected(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	submissionLog := &fakeLog{}

	handler := &SubmitHandler{
		Sessions:     sessions,
		Store:        newFakeStore(),
		Log:          submissionLog,
		AVScanner:    &capturingScanner{},
		AVScanBudget: 5, // far below the log's decompressed length
	}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusOK {
		t.Fatalf("status = %d, want 200: exceeding the budget is recorded, not rejected", status)
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	got := submissionLog.entries[0].Scan
	if got == nil || got.Complete || got.Bytes != 5 {
		t.Errorf("Scan = %+v, want {Complete:false Bytes:5}", got)
	}
}

func TestSubmitHandler_RejectsInfectedLog(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	store := newFakeStore()

	// Clean on metadata.json, infected on the log: proves the log windows
	// are verdicted too, not just the first scan.
	scanner := &capturingScanner{
		verdicts: []clamav.Verdict{{}, {Infected: true, Signature: "Test.Sig"}},
	}
	handler := &SubmitHandler{Sessions: sessions, Store: store, AVScanner: scanner}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", status)
	}
	if _, ok := store.get("samourai-20260709-1830UTC.tar.gz"); ok {
		t.Error("an infected archive was stored")
	}
}

func TestSubmitHandler_ScannerFailureOnTheLogIs503(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	store := newFakeStore()

	scanner := &capturingScanner{errs: []error{nil, errors.New("connection refused")}}
	handler := &SubmitHandler{Sessions: sessions, Store: store, AVScanner: scanner}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: a scan that could not be completed fails closed", status)
	}
	if _, ok := store.get("samourai-20260709-1830UTC.tar.gz"); ok {
		t.Error("an unscanned archive was stored")
	}
}

// blockingScanner lets a test observe the handler *during* the scan. Without
// it every assertion about progress would run after the handler returned, by
// which point the deferred Done has already removed the entry — and a test
// that passes against a handler publishing nothing at all proves nothing.
type blockingScanner struct {
	mu       sync.Mutex
	calls    int
	scanning chan struct{} // closed once the log's window is being scanned
	release  chan struct{} // closed by the test to let the handler finish
}

func (s *blockingScanner) Scan(ctx context.Context, r io.Reader) (clamav.Verdict, error) {
	if _, err := io.ReadAll(r); err != nil {
		return clamav.Verdict{}, err
	}

	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()

	// Call 1 is metadata.json; call 2 is the log's only window, which is the
	// phase this test is about.
	if n == 2 {
		close(s.scanning)
		<-s.release
	}
	return clamav.Verdict{}, nil
}

func TestSubmitHandler_PublishesProgressWhileScanning(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	tracker := NewProgressTracker()
	scanner := &blockingScanner{scanning: make(chan struct{}), release: make(chan struct{})}

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     newFakeStore(),
		AVScanner: scanner,
		Progress:  tracker,
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Built here, not in the goroutine below: these helpers call t.Fatalf,
	// which is only valid on the test's own goroutine.
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", buildValidArchive(t, operatorAddr.String()))
	token := sessions.Issue(operatorAddr)

	status := make(chan int, 1)
	go func() {
		req, err := http.NewRequest(http.MethodPost, srv.URL, body)
		if err != nil {
			status <- 0
			return
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			status <- 0
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		status <- resp.StatusCode
	}()

	select {
	case <-scanner.scanning:
	case <-time.After(10 * time.Second):
		t.Fatal("the log scan never started")
	}

	got, ok := tracker.Get(operatorAddr.String())
	if !ok {
		t.Fatal("no progress published while the scan was running")
	}
	if got.Phase != PhaseScanning {
		t.Errorf("Phase = %q, want %q", got.Phase, PhaseScanning)
	}
	if got.Bytes == 0 {
		t.Error("Bytes = 0 mid-scan, want the bytes already streamed to the scanner")
	}

	close(scanner.release)
	if code := <-status; code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if _, ok := tracker.Get(operatorAddr.String()); ok {
		t.Error("progress outlived the handler; the deferred Done must remove it")
	}
}

func TestSubmitHandler_WithoutATrackerBehavesAsBefore(t *testing.T) {
	// cmd/portal-dev builds the handler this way, and so does every other
	// test in this file. A nil tracker must be a no-op, not a panic.
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     newFakeStore(),
		AVScanner: &capturingScanner{},
		// Progress deliberately nil.
	}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
}
