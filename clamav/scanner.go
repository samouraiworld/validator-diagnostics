// Package clamav scans submitted archives for malware via a clamd
// daemon, as defense in depth alongside submission.ValidateArchive's
// structural checks (prd.md, "Security Considerations" — "Run an
// antivirus scan (e.g. ClamAV) on extracted content"). Implementations
// must never execute, parse, or interpret the scanned content beyond
// what the wire protocol itself requires.
package clamav

import (
	"context"
	"io"
)

// Verdict is the outcome of a completed scan. It's only meaningful
// when Scan returns a nil error — a non-nil error means the scan
// itself could not be completed (unreachable daemon, timeout,
// malformed response), which callers must treat as "unknown", never as
// "clean". portal.SubmitHandler is fail-closed on that distinction: an
// error rejects the upload just as surely as Verdict.Infected does.
type Verdict struct {
	Infected  bool
	Signature string // populated when Infected
}

// Scanner scans r for malware.
type Scanner interface {
	Scan(ctx context.Context, r io.Reader) (Verdict, error)
}
