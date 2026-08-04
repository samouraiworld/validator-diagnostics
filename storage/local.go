package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// LocalStore implements Store by writing to a local directory. Meant
// for local development/testing (e.g. cmd/portal-dev) — not a
// production backend; prd.md's "Option 2 — Object Storage" is S3Store.
type LocalStore struct {
	Dir string
}

var _ Store = LocalStore{}

// validKey rejects degenerate keys (empty, ".", "..", or containing a path
// separator) before they reach the filesystem. Both Save and Delete build
// dest by joining key onto s.Dir, and a degenerate key can resolve to s.Dir
// itself — for Delete that means os.Remove would delete the whole upload
// directory.
func validKey(key string) error {
	if key == "" || key == "." || key == ".." || strings.ContainsRune(key, filepath.Separator) {
		return fmt.Errorf("refusing to use invalid key %q", key)
	}
	return nil
}

func (s LocalStore) Save(ctx context.Context, key string, body io.Reader, size int64) error {
	if err := validKey(key); err != nil {
		return err
	}

	// key comes from submission.ValidateFilename's moniker charset,
	// which already excludes "/", so this Clean is a defensive
	// second layer rather than the only guard against escaping Dir.
	dest := filepath.Join(s.Dir, filepath.Clean(string(filepath.Separator)+key))

	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("unable to create %s: %w", dest, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, body); err != nil {
		return fmt.Errorf("unable to write %s: %w", dest, err)
	}

	return nil
}

func (s LocalStore) Delete(ctx context.Context, key string) error {
	if err := validKey(key); err != nil {
		return err
	}

	dest := filepath.Join(s.Dir, filepath.Clean(string(filepath.Separator)+key))

	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unable to delete %s: %w", dest, err)
	}
	return nil
}
