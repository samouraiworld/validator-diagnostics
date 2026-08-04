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

func TestLocalStore_Delete(t *testing.T) {
	dir := t.TempDir()
	store := LocalStore{Dir: dir}

	const key = "samourai-20260709-1830UTC.tar.gz"
	if err := store.Save(context.Background(), key, strings.NewReader("content"), 7); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, key)); !os.IsNotExist(err) {
		t.Errorf("file still exists after Delete (err = %v)", err)
	}
}

func TestLocalStore_DeleteMissingKeyIsNotError(t *testing.T) {
	dir := t.TempDir()
	store := LocalStore{Dir: dir}

	if err := store.Delete(context.Background(), "never-uploaded.tar.gz"); err != nil {
		t.Errorf("Delete of a missing key: %v, want nil (idempotent)", err)
	}
}

func TestLocalStore_DeleteRefusesEmptyKey(t *testing.T) {
	dir := t.TempDir()
	store := LocalStore{Dir: dir}

	if err := store.Delete(context.Background(), ""); err == nil {
		t.Fatal("Delete with an empty key: got nil error, want a rejection")
	}

	if _, err := os.Stat(dir); err != nil {
		t.Errorf("upload directory was removed (Stat: %v), want it untouched", err)
	}
}

func TestLocalStore_SaveRefusesEmptyKey(t *testing.T) {
	dir := t.TempDir()
	store := LocalStore{Dir: dir}

	if err := store.Save(context.Background(), "", strings.NewReader("x"), 1); err == nil {
		t.Fatal("Save with an empty key: got nil error, want a rejection")
	}
}
