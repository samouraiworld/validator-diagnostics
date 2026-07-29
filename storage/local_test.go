package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalStore_Save(t *testing.T) {
	dir := t.TempDir()
	store := LocalStore{Dir: dir}

	const key = "samourai-20260709-1830UTC.tar.gz"
	content := "fake archive bytes"

	if err := store.Save(context.Background(), key, strings.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, key))
	if err != nil {
		t.Fatalf("reading saved file: %v", err)
	}
	if string(data) != content {
		t.Errorf("saved content = %q, want %q", data, content)
	}
}

func TestLocalStore_RefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	store := LocalStore{Dir: dir}

	const key = "samourai-20260709-1830UTC.tar.gz"

	if err := store.Save(context.Background(), key, strings.NewReader("first"), 5); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := store.Save(context.Background(), key, strings.NewReader("second"), 6); err == nil {
		t.Fatal("expected the second Save with the same key to fail, got nil")
	}
}
