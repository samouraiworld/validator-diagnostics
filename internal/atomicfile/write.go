// Package atomicfile writes a file in a way that a crash or a full disk
// can't leave half-finished. Both JSON stores in this repo
// (exercise.FileStore, scoring.Store) rewrite their whole file on every
// update, so a torn write doesn't corrupt one record — it loses all of
// them at once.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write replaces path with data in one step: write a temp file in the
// same directory, then rename it over the target, which is atomic on
// POSIX. os.WriteFile would truncate the existing file first, so an
// interrupted write would leave a half-written file that fails to parse
// on the next read.
func Write(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Cleans up every failure path below; a no-op once the rename
	// succeeded, since the temp name no longer exists by then.
	defer os.Remove(tmp)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	// os.CreateTemp always creates with 0600.
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Syncing the data isn't enough on its own: on ext4 and friends the
	// rename is a directory operation, and without this the entry can
	// still be lost to a power cut even though the bytes were durable.
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
