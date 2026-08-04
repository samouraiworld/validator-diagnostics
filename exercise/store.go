package exercise

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileStore persists a single Config to a JSON file, guarded by a
// mutex. Unlike portal.FileLog (append-only submissions), the exercise
// config is replaced wholesale each time an admin updates it, so this
// is a read-modify-write store, not an append log.
type FileStore struct {
	mu   sync.Mutex
	path string
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Get returns the current config, or the zero Config (Configured() ==
// false) if none has been saved yet.
func (s *FileStore) Get() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("unable to read exercise config %s: %w", s.path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("unable to parse exercise config %s: %w", s.path, err)
	}
	return cfg, nil
}

// Set validates cfg and persists it, replacing whatever was stored
// before. An invalid cfg is rejected without touching the file.
func (s *FileStore) Set(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal exercise config: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := writeFileAtomic(s.path, data, 0o644); err != nil {
		return fmt.Errorf("unable to write exercise config %s: %w", s.path, err)
	}
	return nil
}

// writeFileAtomic replaces path with data in one step: write a temp file
// in the same directory, then rename it over the target, which is atomic
// on POSIX. os.WriteFile would truncate the existing file first, so a
// crash or a full disk mid-write would leave a half-written file that
// fails to parse on the next read — losing the whole exercise config
// rather than just the update that failed.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
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
	return os.Rename(tmp, path)
}
