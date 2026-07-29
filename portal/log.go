package portal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is one recorded successful submission, written by SubmitHandler
// and read back by the admin dashboard.
type Entry struct {
	Moniker         string    `json:"moniker"`
	OperatorAddress string    `json:"operator_address"`
	Filename        string    `json:"filename"`
	SubmittedAt     time.Time `json:"submitted_at"`
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
