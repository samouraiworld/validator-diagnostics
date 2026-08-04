package clamav

import (
	"context"
	"io"
)

// NoopScanner always returns a clean verdict without contacting any
// daemon. Used where a real clamd isn't available (cmd/portal-dev,
// tests) — never wire this into a production deployment; cmd/portal
// only falls back to it when -clamav-addr is left empty, which its own
// flag help text calls out.
type NoopScanner struct{}

var _ Scanner = NoopScanner{}

func (NoopScanner) Scan(ctx context.Context, r io.Reader) (Verdict, error) {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return Verdict{}, err
	}
	return Verdict{}, nil
}
