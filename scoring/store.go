package scoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	return os.WriteFile(s.path, data, 0o644)
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
