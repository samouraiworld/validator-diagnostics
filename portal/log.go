package portal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/samourai/validator-diagnostics/clamav"
	"github.com/samourai/validator-diagnostics/internal/atomicfile"
)

// Entry is one recorded successful submission, written by SubmitHandler
// and read back by the admin dashboard. ID is the join key between
// this append-only log and the scoring package's per-submission
// records (see scoring.Store), which need to support updates that
// FileLog's append-only model doesn't.
type Entry struct {
	ID              string    `json:"id"`
	Moniker         string    `json:"moniker"`
	OperatorAddress string    `json:"operator_address"`
	Filename        string    `json:"filename"`
	SubmittedAt     time.Time `json:"submitted_at"`

	// SentryEnabled is metadata.json's declaration, kept here because the
	// summary needs it to tell "runs a sentry but sent no sentry log" from
	// "runs no sentry" — a distinction the scoring record cannot make, and
	// one only worth flagging in the first case.
	SentryEnabled bool `json:"sentry_enabled,omitempty"`

	// Scan is what the antivirus actually examined. Non-nil is an
	// affirmative claim: a real Scanner was wired and returned a clean
	// verdict over metadata.json plus Bytes bytes of decompressed
	// content from the submitted logs — Bytes counts only the logs, since
	// metadata.json is scanned separately, whole, and is not counted
	// towards it. Nil claims nothing — either the entry predates windowed
	// scanning, or no scanner was wired at all. There is nothing in
	// between: a scan that errors, or finds something, fails the
	// submission outright, so no Entry is written for it.
	//
	// clamav.Coverage's JSON tags are a persisted format from here on —
	// they are what submissions.jsonl holds.
	Scan *clamav.Coverage `json:"scan,omitempty"`
}

// NewSubmissionID returns a random, URL-safe identifier for a new
// Entry.
func NewSubmissionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("unable to generate submission ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Log records successful submissions. SubmitHandler treats a nil Log as
// "logging disabled" — the field is optional.
type Log interface {
	Record(ctx context.Context, e Entry) error
}

// FileLog is a Log backed by an append-only JSON-lines file. Simple
// enough for a single exercise's admin dashboard — no database.
type FileLog struct {
	mu   sync.Mutex
	path string
}

func NewFileLog(path string) *FileLog {
	return &FileLog{path: path}
}

func (l *FileLog) Record(ctx context.Context, e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("unable to open submission log %s: %w", l.path, err)
	}
	defer f.Close()

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("unable to marshal log entry: %w", err)
	}
	data = append(data, '\n')

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("unable to write log entry: %w", err)
	}

	return nil
}

// Entries returns every recorded entry, oldest first. A missing log file
// means no submissions yet — not an error.
func (l *FileLog) Entries() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.readEntries()
}

// readEntries reads and parses every entry currently in the log.
// Callers must hold l.mu.
func (l *FileLog) readEntries() ([]Entry, error) {
	data, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unable to read submission log %s: %w", l.path, err)
	}

	entries := []Entry{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("unable to parse submission log line: %w", err)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to scan submission log: %w", err)
	}

	return entries, nil
}

// Delete removes the entry with the given ID, rewriting the log file
// with atomicfile.Write so a torn write can't corrupt the remaining
// entries. found reports whether an entry with that ID existed.
func (l *FileLog) Delete(id string) (found bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.readEntries()
	if err != nil {
		return false, err
	}

	remaining := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.ID == id {
			found = true
			continue
		}
		remaining = append(remaining, e)
	}
	if !found {
		return false, nil
	}

	var buf bytes.Buffer
	for _, e := range remaining {
		data, err := json.Marshal(e)
		if err != nil {
			return false, fmt.Errorf("unable to marshal log entry: %w", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	if err := atomicfile.Write(l.path, buf.Bytes(), 0o644); err != nil {
		return false, fmt.Errorf("unable to write submission log %s: %w", l.path, err)
	}

	return true, nil
}
