package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// chunkSize is how much of the scanned input ClamdScanner buffers per
// INSTREAM chunk. clamd's own default StreamMaxLength is 25 MiB per
// chunk; staying well below that keeps memory use predictable
// regardless of what a given deployment configures.
const chunkSize = 1 << 20 // 1 MiB

const defaultTimeout = 30 * time.Second

// ClamdScanner scans over clamd's INSTREAM protocol: a stream of
// 4-byte-big-endian-length-prefixed chunks terminated by a
// zero-length chunk, answered with a single response line
// ("stream: OK" or "stream: <signature> FOUND").
//
// Manual smoke test against a real daemon (not run in CI, not covered
// by clamd_test.go's fake server): start a real clamd
// (`docker run -d -p 3310:3310 clamav/clamav`, then wait ~60s for the
// virus database to load) and run a throwaway program that calls
// ClamdScanner{Addr: "localhost:3310"}.Scan against the standard
// EICAR test string (https://www.eicar.org/download-anti-malware-testfile/)
// — a clean clamd install must report that string FOUND, and a benign
// string must report OK.
type ClamdScanner struct {
	// Addr is a "host:port" TCP address, or, prefixed with "unix:", a
	// Unix socket path (e.g. "unix:/var/run/clamav/clamd.ctl").
	Addr string

	// Timeout bounds the whole scan, dial included. Zero uses a 30s
	// default.
	Timeout time.Duration
}

var _ Scanner = ClamdScanner{}

func (c ClamdScanner) dial(ctx context.Context) (net.Conn, error) {
	network, addr := "tcp", c.Addr
	if rest, ok := strings.CutPrefix(c.Addr, "unix:"); ok {
		network, addr = "unix", rest
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Scan streams r to clamd over a single INSTREAM session. Any failure
// to complete the exchange (dial, write, or an unreadable/unrecognized
// response) is returned as an error — portal.SubmitHandler treats that
// as fail-closed, the same as a real Verdict{Infected: true}.
func (c ClamdScanner) Scan(ctx context.Context, r io.Reader) (Verdict, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return Verdict{}, fmt.Errorf("clamav: unable to connect to %s: %w", c.Addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte("nINSTREAM\n")); err != nil {
		return Verdict{}, fmt.Errorf("clamav: unable to start INSTREAM: %w", err)
	}

	// Created up front, not just before the final read: clamd answers a
	// stream that exceeds its StreamMaxLength by writing an ERROR line
	// and closing the connection immediately, so the response may be
	// waiting for us while we are still writing chunks (see writeFailure).
	br := bufio.NewReader(conn)

	buf := make([]byte, chunkSize)
	lenPrefix := make([]byte, 4)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenPrefix, uint32(n))
			if _, err := conn.Write(lenPrefix); err != nil {
				return Verdict{}, writeFailure("writing chunk length", err, br)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return Verdict{}, writeFailure("writing chunk", err, br)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Verdict{}, fmt.Errorf("clamav: reading input: %w", readErr)
		}
	}

	binary.BigEndian.PutUint32(lenPrefix, 0)
	if _, err := conn.Write(lenPrefix); err != nil {
		return Verdict{}, writeFailure("writing terminating chunk", err, br)
	}

	line, err := br.ReadString('\n')
	if err != nil {
		return Verdict{}, fmt.Errorf("clamav: no response from daemon: %w", err)
	}
	line = strings.TrimSpace(line)

	switch {
	case strings.HasSuffix(line, "ERROR"):
		// clamd reporting a problem with the request itself rather than a
		// verdict — most commonly "INSTREAM size limit exceeded." when the
		// upload is larger than clamd's StreamMaxLength. Still fail-closed,
		// but named distinctly so an operator can tell a misconfigured size
		// limit from a daemon that is down or speaking gibberish.
		return Verdict{}, fmt.Errorf("clamav: clamd protocol error: %s", line)
	case strings.HasSuffix(line, "OK"):
		return Verdict{}, nil
	case strings.HasSuffix(line, "FOUND"):
		rest := strings.TrimSuffix(strings.TrimPrefix(line, "stream:"), "FOUND")
		return Verdict{Infected: true, Signature: strings.TrimSpace(rest)}, nil
	default:
		return Verdict{}, fmt.Errorf("clamav: unrecognized response %q", line)
	}
}

// writeFailure turns a mid-stream write error into the most informative
// error available. When clamd rejects a stream outright (size limit
// exceeded, database not loaded, ...) it writes its ERROR line and hangs
// up straight away, so on our side the first symptom is usually a broken
// pipe on the next chunk write rather than a response line — check for a
// pending response before reporting the raw write error. Either way this
// returns an error, keeping the scan fail-closed.
func writeFailure(stage string, writeErr error, br *bufio.Reader) error {
	if line, err := br.ReadString('\n'); err == nil {
		if line = strings.TrimSpace(line); strings.HasSuffix(line, "ERROR") {
			return fmt.Errorf("clamav: clamd protocol error: %s", line)
		}
	}
	return fmt.Errorf("clamav: %s: %w", stage, writeErr)
}
