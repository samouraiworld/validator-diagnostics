package exercise

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileStore_GetOnMissingFile(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "does-not-exist.json"))

	cfg, err := store.Get()
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if cfg.Configured() {
		t.Errorf("Get() on a missing file = %+v, want the zero Config", cfg)
	}
}

func TestFileStore_SetAndGet(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	want := validConfig()

	if err := store.Set(want); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := store.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.AnnouncedAt.Equal(want.AnnouncedAt) || got.ExpectedGenesisSHA256 != want.ExpectedGenesisSHA256 {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
}

func TestFileStore_SetWritesAtomically(t *testing.T) {
	// The write goes through a temp file renamed over the target, so the
	// target must be the only file left behind (no *.tmp debris) and it
	// must carry the store's own 0644, not os.CreateTemp's 0600.
	dir := t.TempDir()
	path := filepath.Join(dir, "exercise.json")
	store := NewFileStore(path)

	if err := store.Set(validConfig()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Set(validConfig()); err != nil {
		t.Fatalf("Set: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "exercise.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory contains %v, want only exercise.json", names)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %v, want 0644", perm)
	}
}

func TestFileStore_SetRejectsInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exercise.json")
	store := NewFileStore(path)

	cfg := validConfig()
	cfg.DeadlineAt = cfg.AnnouncedAt
	if err := store.Set(cfg); err == nil {
		t.Fatal("Set with an invalid config: expected an error, got nil")
	}

	got, err := store.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Configured() {
		t.Error("a rejected Set should not have persisted anything")
	}
}

func TestFileStore_SetReplacesPreviousConfig(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))

	first := validConfig()
	if err := store.Set(first); err != nil {
		t.Fatalf("Set(first): %v", err)
	}

	second := validConfig()
	second.ExpectedGenesisSHA256 = "different-hash"
	if err := store.Set(second); err != nil {
		t.Fatalf("Set(second): %v", err)
	}

	got, err := store.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ExpectedGenesisSHA256 != "different-hash" {
		t.Errorf("ExpectedGenesisSHA256 = %q, want the second Set's value", got.ExpectedGenesisSHA256)
	}
}
