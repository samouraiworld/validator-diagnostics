package exercise

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigHandler_GetBeforeAnySet(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var cfg Config
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Configured() {
		t.Errorf("GET before any POST = %+v, want the zero Config", cfg)
	}
}

func TestConfigHandler_PostThenGet(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	cfg := validConfig()
	body, _ := json.Marshal(cfg)

	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", resp.StatusCode)
	}

	getResp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getResp.Body.Close()

	var got Config
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ExpectedGenesisSHA256 != cfg.ExpectedGenesisSHA256 {
		t.Errorf("ExpectedGenesisSHA256 = %q, want %q", got.ExpectedGenesisSHA256, cfg.ExpectedGenesisSHA256)
	}
}

func TestConfigHandler_PostRejectsInvalidConfig(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	cfg := validConfig()
	cfg.DeadlineAt = cfg.AnnouncedAt
	body, _ := json.Marshal(cfg)

	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestConfigHandler_PostRejectsNonJSONContentType(t *testing.T) {
	// The shape a cross-site CSRF attempt takes: a form POST carrying a
	// JSON-shaped body under a "simple request" content type, riding on
	// the admin's cached Basic credentials. It must be refused before the
	// body is decoded, leaving the stored config untouched.
	body, _ := json.Marshal(validConfig())

	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""} {
		t.Run("content-type "+contentType, func(t *testing.T) {
			store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
			srv := httptest.NewServer(ConfigHandler(store))
			defer srv.Close()

			resp, err := http.Post(srv.URL, contentType, bytes.NewReader(body))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", resp.StatusCode)
			}

			stored, err := store.Get()
			if err != nil {
				t.Fatalf("store.Get: %v", err)
			}
			if stored.Configured() {
				t.Errorf("stored config = %+v, want the request to have been rejected before anything was written", stored)
			}
		})
	}
}

func TestConfigHandler_PostAcceptsJSONWithCharset(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	body, _ := json.Marshal(validConfig())
	resp, err := http.Post(srv.URL, "application/json; charset=utf-8", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestConfigHandler_PostRejectsUnknownFields(t *testing.T) {
	// POST replaces the config wholesale, so a misspelt key isn't a
	// no-op: the field it was meant to set reverts to its zero value. A
	// typo'd expected_genesis_sha256 leaves an empty expected hash, and
	// every subsequent submission is then reported as a genesis mismatch
	// with nothing pointing at the config as the cause.
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	valid := validConfig()
	if err := store.Set(valid); err != nil {
		t.Fatalf("store.Set: %v", err)
	}

	body := `{
		"announced_at": "2026-07-08T18:00:00Z",
		"deadline_at": "2026-07-09T18:00:00Z",
		"investigation_window_start": "2026-07-08T18:00:00Z",
		"investigation_window_end": "2026-07-09T18:00:00Z",
		"typo_genesis_sha256": "abc123",
		"observations": "just an update"
	}`
	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}

	stored, err := store.Get()
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.ExpectedGenesisSHA256 != valid.ExpectedGenesisSHA256 {
		t.Errorf("ExpectedGenesisSHA256 = %q, want the previous value %q left intact",
			stored.ExpectedGenesisSHA256, valid.ExpectedGenesisSHA256)
	}
}

func TestConfigHandler_PostReportsStorageFailureAsServerError(t *testing.T) {
	// store.Set returns validation errors and write errors through the
	// same channel. Reporting a full disk or an unwritable path as 400
	// tells the admin their input was wrong, so they retype a correct
	// form indefinitely; it also echoes the filesystem path back to them.
	dir := t.TempDir()
	unwritable := filepath.Join(dir, "readonly")
	if err := os.Mkdir(unwritable, 0o500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unwritable, 0o700) })

	store := NewFileStore(filepath.Join(unwritable, "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	body, _ := json.Marshal(validConfig())
	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — the config was valid, the disk was not", resp.StatusCode)
	}

	detail, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(detail), unwritable) {
		t.Errorf("response body leaks the storage path: %q", detail)
	}
}

func TestConfigHandler_PostRejectsMalformedJSON(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
