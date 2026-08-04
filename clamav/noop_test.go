package clamav

import (
	"context"
	"strings"
	"testing"
)

func TestNoopScanner_AlwaysClean(t *testing.T) {
	verdict, err := (NoopScanner{}).Scan(context.Background(), strings.NewReader("anything at all"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if verdict.Infected {
		t.Error("NoopScanner reported Infected = true, want false")
	}
}

func TestNoopScanner_DrainsReader(t *testing.T) {
	r := strings.NewReader("some content")
	if _, err := (NoopScanner{}).Scan(context.Background(), r); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.Len() != 0 {
		t.Error("NoopScanner did not fully read its input")
	}
}
