package scoring

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStore_GetOnMissingFile(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "does-not-exist.json"))

	_, ok, err := store.Get("some-id")
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if ok {
		t.Error("Get on an empty store: ok = true, want false")
	}
}

func TestStore_SetAndGet(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "scores.json"))
	want := Result{SubmissionID: "abc", UploadTimeScore: 20, MetadataScore: 20, LogQualityScore: 15, Scored: true}

	if err := store.Set(want); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, ok, err := store.Get("abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get: ok = false, want true")
	}
	if got.UploadTimeScore != 20 || got.LogQualityScore != 15 {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
}

func TestStore_SetWritesAtomically(t *testing.T) {
	// The write goes through a temp file renamed over the target, so the
	// target must be the only file left behind (no *.tmp debris) and it
	// must carry the store's own 0644, not os.CreateTemp's 0600.
	dir := t.TempDir()
	path := filepath.Join(dir, "scores.json")
	store := NewStore(path)

	if err := store.Set(Result{SubmissionID: "abc", Scored: true}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Set(Result{SubmissionID: "def", Scored: true}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "scores.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory contains %v, want only scores.json", names)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %v, want 0644", perm)
	}
}

func TestStore_SetUpdatesInPlace(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "scores.json"))

	if err := store.Set(Result{SubmissionID: "abc", UploadTimeScore: 20}); err != nil {
		t.Fatalf("Set(first): %v", err)
	}

	ack := 10
	if err := store.Set(Result{SubmissionID: "abc", UploadTimeScore: 20, AckTimeScore: &ack}); err != nil {
		t.Fatalf("Set(second): %v", err)
	}

	got, ok, err := store.Get("abc")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.AckTimeScore == nil || *got.AckTimeScore != 10 {
		t.Errorf("AckTimeScore = %v, want a pointer to 10", got.AckTimeScore)
	}
}

func TestStore_List(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := store.Set(Result{SubmissionID: "a"}); err != nil {
		t.Fatalf("Set(a): %v", err)
	}
	if err := store.Set(Result{SubmissionID: "b"}); err != nil {
		t.Fatalf("Set(b): %v", err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len(list) = %d, want 2", len(list))
	}
}
