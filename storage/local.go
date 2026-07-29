package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LocalStore implements Store by writing to a local directory. Meant
// for local development/testing (e.g. cmd/portal-dev) — not a
// production backend; prd.md's "Option 2 — Object Storage" is S3Store.
type LocalStore struct {
	Dir string
}

var _ Store = LocalStore{}

func (s LocalStore) Save(ctx context.Context, key string, body io.Reader, size int64) error {
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
