package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeClamd starts a TCP listener that speaks just enough of the
// INSTREAM protocol to test ClamdScanner against, without needing a
// real clamd: it reads chunks until the terminating zero-length chunk,
// then writes back response.
func fakeClamd(t *testing.T, response string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		cmd, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(cmd) != "nINSTREAM" {
			return
		}

		for {
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(br, lenBuf); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(lenBuf)
			if n == 0 {
				break
			}
			if _, err := io.CopyN(io.Discard, br, int64(n)); err != nil {
				return
			}
		}

		_, _ = conn.Write([]byte(response))
	}()

	return ln.Addr().String()
}

func TestClamdScanner_Clean(t *testing.T) {
	addr := fakeClamd(t, "stream: OK\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	verdict, err := scanner.Scan(context.Background(), strings.NewReader("harmless content"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if verdict.Infected {
		t.Error("Infected = true, want false")
	}
}

func TestClamdScanner_Infected(t *testing.T) {
	addr := fakeClamd(t, "stream: Eicar-Test-Signature FOUND\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	verdict, err := scanner.Scan(context.Background(), strings.NewReader("fake eicar payload"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !verdict.Infected {
		t.Fatal("Infected = false, want true")
	}
	if verdict.Signature != "Eicar-Test-Signature" {
		t.Errorf("Signature = %q, want %q", verdict.Signature, "Eicar-Test-Signature")
	}
}

func TestClamdScanner_LargeInput(t *testing.T) {
	// Exercises the multi-chunk path (chunkSize is 1 MiB): 3 MiB of
	// input should be split across multiple INSTREAM chunks.
	addr := fakeClamd(t, "stream: OK\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	large := strings.NewReader(strings.Repeat("a", 3<<20))
	verdict, err := scanner.Scan(context.Background(), large)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if verdict.Infected {
		t.Error("Infected = true, want false")
	}
}

func TestClamdScanner_Unreachable(t *testing.T) {
	// Port 1 is a privileged port nothing is listening on; dialing it
	// fails fast with "connection refused" rather than timing out.
	scanner := ClamdScanner{Addr: "127.0.0.1:1", Timeout: 2 * time.Second}

	_, err := scanner.Scan(context.Background(), strings.NewReader("content"))
	if err == nil {
		t.Fatal("expected an error for an unreachable daemon, got nil")
	}
}

func TestClamdScanner_MalformedResponse(t *testing.T) {
	addr := fakeClamd(t, "garbage\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	_, err := scanner.Scan(context.Background(), strings.NewReader("content"))
	if err == nil {
		t.Fatal("expected an error for an unrecognized response, got nil")
	}
}

func TestClamdScanner_TruncatedResponse(t *testing.T) {
	// The fake server writes a response with no trailing newline and
	// then closes the connection, simulating a stalled/hung daemon
	// whose reply never fully arrives (e.g. the connection is dropped,
	// or a deadline fires, mid-line after "stream: OK" but before the
	// terminating '\n'). bufio.Reader.ReadString returns a non-nil
	// error in this case even though it already delivered bytes that
	// happen to look like a complete, valid response — Scan must treat
	// that as a failed exchange, not silently accept the partial line
	// as a clean verdict.
	addr := fakeClamd(t, "stream: OK")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	verdict, err := scanner.Scan(context.Background(), strings.NewReader("content"))
	if err == nil {
		t.Fatalf("expected an error for a truncated response, got nil (verdict=%+v)", verdict)
	}
}
