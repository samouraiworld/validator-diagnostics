package scoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store persists Result records to a single JSON file, keyed by
// SubmissionID. Same read-modify-write-under-mutex shape as
// exercise.FileStore — records get updated in place (manual fields
// arrive later), unlike portal.FileLog's append-only submissions log.
type Store struct {
	mu   sync.Mutex
	path string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func (s *Store) all() (map[string]Result, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Result{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unable to read scores %s: %w", s.path, err)
	}
	// A present-but-empty file is zero records, same as no file. Left to
	// json.Unmarshal it is a parse error, and since the dashboard 500s on
	// an unreadable store (deliberately — see portal.AdminSubmissionsHandler)
	// a stray `touch` would take the whole admin view down with no way to
	// recover through the UI. A corrupt file still errors; that one is
	// worth surfacing rather than silently overwriting.
	if len(data) == 0 {
		return map[string]Result{}, nil
	}
	var results map[string]Result
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("unable to parse scores %s: %w", s.path, err)
	}
	return results, nil
}

func (s *Store) save(results map[string]Result) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal scores: %w", err)
	}
	if err := writeFileAtomic(s.path, data, 0o644); err != nil {
		return fmt.Errorf("unable to write scores %s: %w", s.path, err)
	}
	return nil
}

// writeFileAtomic replaces path with data in one step: write a temp file
// in the same directory, then rename it over the target, which is atomic
// on POSIX. os.WriteFile would truncate the existing file first, so a
// crash or a full disk mid-write would leave a half-written file that
// fails to parse on the next read — losing every stored score at once,
// not just the record being written.
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

// Get returns the record for id, or (Result{}, false, nil) if none
// exists yet.
func (s *Store) Get(id string) (Result, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	results, err := s.all()
	if err != nil {
		return Result{}, false, err
	}
	r, ok := results[id]
	return r, ok, nil
}

// Set writes or replaces the record for r.SubmissionID.
func (s *Store) Set(r Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	results, err := s.all()
	if err != nil {
		return err
	}
	results[r.SubmissionID] = r
	return s.save(results)
}

// List returns every record, in no particular order.
func (s *Store) List() ([]Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	results, err := s.all()
	if err != nil {
		return nil, err
	}
	list := make([]Result, 0, len(results))
	for _, r := range results {
		list = append(list, r)
	}
	return list, nil
}
