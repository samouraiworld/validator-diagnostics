package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWrite_ReplacesContentAndLeavesNoDebris(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")

	if err := Write(path, []byte("first"), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := Write(path, []byte("second"), 0o644); err != nil {
		t.Fatalf("Write (replace): %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("content = %q, want %q", got, "second")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only the target — temp files must not survive", names)
	}
}

func TestWrite_AppliesPermNotCreateTempDefault(t *testing.T) {
	// os.CreateTemp always creates 0600, so without an explicit Chmod the
	// stores' files would end up unreadable to anyone but the portal user.
	path := filepath.Join(t.TempDir(), "store.json")
	if err := Write(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("perm = %04o, want 0644", got)
	}
}

func TestWrite_FailureLeavesTheExistingFileIntact(t *testing.T) {
	// The property the whole package exists for: a write that can't
	// complete must not destroy what was already there. os.WriteFile
	// would have truncated it before failing.
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	if err := Write(path, []byte("original"), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Make the temp file uncreatable without touching the target.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := Write(path, []byte("replacement"), 0o644); err == nil {
		t.Fatal("Write into a read-only directory succeeded, want an error")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "original" {
		t.Errorf("content = %q, want the original left untouched by a failed write", got)
	}
}
