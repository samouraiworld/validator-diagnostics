package exercise

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

	if err := os.WriteFile(s.path, data, 0o644); err != nil {
		return fmt.Errorf("unable to write exercise config %s: %w", s.path, err)
	}
	return nil
}
