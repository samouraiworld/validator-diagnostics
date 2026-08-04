package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
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

	go serveOneClamdResponse(t, ln, response)

	return ln.Addr().String()
}

// serveOneClamdResponse accepts one connection on ln, reads a complete
// INSTREAM session off it, and answers with response. Split out of
// fakeClamd so the same protocol handling can back a Unix socket
// listener too.
func serveOneClamdResponse(t *testing.T, ln net.Listener, response string) {
	t.Helper()

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
}

// fakeClamdEarlyError is fakeClamd's impatient sibling: it reads only
// the first INSTREAM chunk, then writes response and closes the
// connection without draining the rest — the way a real clamd behaves
// when the stream exceeds StreamMaxLength.
func fakeClamdEarlyError(t *testing.T, response string) string {
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

		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(br, lenBuf); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, br, int64(binary.BigEndian.Uint32(lenBuf))); err != nil {
			return
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

func TestClamdScanner_RequiresStreamPrefix(t *testing.T) {
	// INSTREAM answers "stream: ...". Matching on the OK/FOUND suffix
	// alone means any stray line that happens to end in OK — a banner, a
	// reply left over from another command — becomes a clean verdict. In
	// a file whose whole purpose is to never confuse "clean" with "we
	// don't know", an unrecognized line has to be an error.
	for _, response := range []string{
		"Bogus daemon banner OK\n",
		"SOMETHINGELSE: OK\n",
		"OK\n",
	} {
		t.Run(strings.TrimSpace(response), func(t *testing.T) {
			addr := fakeClamd(t, response)
			scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

			verdict, err := scanner.Scan(context.Background(), strings.NewReader("payload"))
			if err == nil {
				t.Fatalf("Scan returned verdict %+v and no error, want an error for an unrecognized response", verdict)
			}
			if verdict.Infected {
				t.Errorf("Infected = true, want the zero Verdict alongside the error")
			}
		})
	}
}

func TestClamdScanner_LimitsExceededIsAnErrorNotAVerdict(t *testing.T) {
	// With AlertExceedsMax on, clamd reports content it gave up scanning
	// (MaxScanSize/MaxFileSize/MaxRecursion/MaxFiles) through the FOUND
	// channel, as a Heuristics.Limits.Exceeded pseudo-signature. That is
	// the opposite of a detection: it means part of the archive was never
	// examined. Reporting it as Infected would tell a validator their
	// submission contains malware on the strength of a scan that did not
	// happen — and the honest answer, "we could not complete the scan",
	// is exactly what the error return means.
	for _, response := range []string{
		"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n",
		"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\n",
	} {
		t.Run(strings.TrimSpace(response), func(t *testing.T) {
			addr := fakeClamd(t, response)
			scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

			verdict, err := scanner.Scan(context.Background(), strings.NewReader("a very large archive"))
			if err == nil {
				t.Fatalf("Scan returned verdict %+v and no error, want an error: the scan was incomplete, not clean and not infected", verdict)
			}
			if verdict.Infected {
				t.Error("Infected = true, want false: an unscanned region is not a detection")
			}
			if !strings.Contains(err.Error(), "Heuristics.Limits.Exceeded") {
				t.Errorf("error = %v, want it to name the limit clamd hit so an operator can raise it", err)
			}
		})
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

func TestClamdScanner_ErrorResponse(t *testing.T) {
	// clamd's answer when a stream is larger than its configured
	// StreamMaxLength. It must fail closed (an error, never a clean
	// verdict) and say so distinctly enough that an operator can tell it
	// apart from the daemon being unreachable or replying with garbage.
	addr := fakeClamd(t, "INSTREAM size limit exceeded. ERROR\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	verdict, err := scanner.Scan(context.Background(), strings.NewReader("content"))
	if err == nil {
		t.Fatalf("expected an error for an ERROR response, got nil (verdict=%+v)", verdict)
	}
	if verdict.Infected {
		t.Error("Infected = true, want false (the scan failed, it found nothing)")
	}
	if !strings.Contains(err.Error(), "clamd protocol error") {
		t.Errorf("error = %q, want it to mention a clamd protocol error", err)
	}
	if !strings.Contains(err.Error(), "INSTREAM size limit exceeded.") {
		t.Errorf("error = %q, want it to quote clamd's own message", err)
	}
}

func TestClamdScanner_ErrorResponseMidStream(t *testing.T) {
	// The realistic shape of the size-limit rejection: clamd writes its
	// ERROR line and closes the connection while the client is still
	// streaming chunks. Depending on socket buffering the client notices
	// either as a failed write or as the response it reads at the end;
	// both paths must surface the same diagnosable error.
	addr := fakeClamdEarlyError(t, "INSTREAM size limit exceeded. ERROR\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	large := strings.NewReader(strings.Repeat("a", 8<<20))
	_, err := scanner.Scan(context.Background(), large)
	if err == nil {
		t.Fatal("expected an error when clamd rejects the stream, got nil")
	}
	if !strings.Contains(err.Error(), "clamd protocol error") {
		t.Errorf("error = %q, want it to mention a clamd protocol error", err)
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

func TestClamdScanner_UnixSocket(t *testing.T) {
	// The deployment uses TCP, but clamd.conf also opens a LocalSocket
	// and ClamdScanner advertises the "unix:" form. Untested until now.
	dir := t.TempDir()
	sock := filepath.Join(dir, "clamd.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveOneClamdResponse(t, ln, "stream: OK\n")

	scanner := ClamdScanner{Addr: "unix:" + sock, Timeout: 5 * time.Second}
	verdict, err := scanner.Scan(context.Background(), strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if verdict.Infected {
		t.Error("Infected = true, want false")
	}
}

func TestClamdScanner_HungDaemonFailsClosedWithinTimeout(t *testing.T) {
	// The fail-closed guarantee under the most likely production failure:
	// clamd accepts the connection but never answers (loading signatures,
	// wedged, out of memory). Scan must return an error, not block the
	// upload indefinitely.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Drain but never reply.
		_, _ = io.Copy(io.Discard, conn)
	}()

	scanner := ClamdScanner{Addr: ln.Addr().String(), Timeout: 300 * time.Millisecond}
	start := time.Now()
	verdict, err := scanner.Scan(context.Background(), strings.NewReader("payload"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Scan returned verdict %+v and no error, want a timeout error", verdict)
	}
	if verdict.Infected {
		t.Error("Infected = true, want the zero Verdict alongside the error")
	}
	if elapsed > 3*time.Second {
		t.Errorf("Scan took %v, want it bounded by the 300ms timeout", elapsed)
	}
}

func TestClamdScanner_CallerContextBeatsLongerTimeout(t *testing.T) {
	// A caller cancelling early must win over ClamdScanner.Timeout, or a
	// client that has already hung up keeps a clamd worker busy.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, conn)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	scanner := ClamdScanner{Addr: ln.Addr().String(), Timeout: time.Hour}
	start := time.Now()
	if _, err := scanner.Scan(ctx, strings.NewReader("payload")); err == nil {
		t.Fatal("Scan succeeded, want the caller's context deadline to end it")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Scan took %v, want the caller's 200ms deadline to win over Timeout: time.Hour", elapsed)
	}
}

func TestClamdScanner_ZeroTimeoutUsesDefault(t *testing.T) {
	// Timeout: 0 must mean "30s", not "no deadline" — an unbounded scan
	// is the fail-open this package is built to avoid.
	addr := fakeClamd(t, "stream: OK\n")
	scanner := ClamdScanner{} // no Timeout set
	scanner.Addr = addr

	if _, err := scanner.Scan(context.Background(), strings.NewReader("payload")); err != nil {
		t.Fatalf("Scan with a zero Timeout: %v", err)
	}
}
