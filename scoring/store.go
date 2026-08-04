package scoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/samourai/validator-diagnostics/internal/atomicfile"
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
	if err := atomicfile.Write(s.path, data, 0o644); err != nil {
		return fmt.Errorf("unable to write scores %s: %w", s.path, err)
	}
	return nil
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

// ByID returns every record keyed by SubmissionID, read under a single
// lock. Callers joining a whole list of submissions against their
// scores want this rather than a Get per row: Get re-reads and re-parses
// the entire file each time, and each call takes the lock separately, so
// a row-by-row join is both O(n) file reads and a set of rows that never
// existed together at any single moment.
func (s *Store) ByID() (map[string]Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.all()
}
