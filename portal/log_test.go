package portal

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestNewSubmissionID_Unique(t *testing.T) {
	a, err := NewSubmissionID()
	if err != nil {
		t.Fatalf("NewSubmissionID: %v", err)
	}
	b, err := NewSubmissionID()
	if err != nil {
		t.Fatalf("NewSubmissionID: %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("NewSubmissionID returned an empty string")
	}
	if a == b {
		t.Error("two calls to NewSubmissionID returned the same ID")
	}
}

func TestFileLog_RecordAndEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	log := NewFileLog(path)

	e1 := Entry{
		ID:              "id-1",
		Moniker:         "samourai",
		OperatorAddress: "g1abc",
		Filename:        "samourai-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Date(2026, 7, 9, 18, 30, 0, 0, time.UTC),
	}
	e2 := Entry{
		ID:              "id-2",
		Moniker:         "other",
		OperatorAddress: "g1def",
		Filename:        "other-20260709-1831UTC.tar.gz",
		SubmittedAt:     time.Date(2026, 7, 9, 18, 31, 0, 0, time.UTC),
	}

	if err := log.Record(context.Background(), e1); err != nil {
		t.Fatalf("Record(e1): %v", err)
	}
	if err := log.Record(context.Background(), e2); err != nil {
		t.Fatalf("Record(e2): %v", err)
	}

	entries, err := log.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Moniker != "samourai" || entries[1].Moniker != "other" {
		t.Errorf("entries out of order or wrong content: %+v", entries)
	}
	if !entries[0].SubmittedAt.Equal(e1.SubmittedAt) {
		t.Errorf("SubmittedAt = %v, want %v", entries[0].SubmittedAt, e1.SubmittedAt)
	}
	if entries[0].ID != "id-1" || entries[1].ID != "id-2" {
		t.Errorf("IDs not round-tripped: entries = %+v", entries)
	}
}

func TestFileLog_EntriesOnMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.jsonl")
	log := NewFileLog(path)

	entries, err := log.Entries()
	if err != nil {
		t.Fatalf("Entries: unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("len(entries) = %d, want 0", len(entries))
	}
}
