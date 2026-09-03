package scoring

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/submission"
)

func gzipLines(t *testing.T, lines ...string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	for _, l := range lines {
		if _, err := gw.Write([]byte(l + "\n")); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

func windowTestConfig() exercise.Config {
	return exercise.Config{
		InvestigationWindowStart: time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
		InvestigationWindowEnd:   time.Date(2026, 7, 9, 18, 30, 0, 0, time.UTC),
		ExpectedGenesisSHA256:    "abc123",
		SupportedGnolandVersions: []string{"v1.0.0", "v1.0.1"},
	}
}

func TestMetadataChecks_GenesisAndVersionMatch(t *testing.T) {
	cfg := windowTestConfig()
	meta := submission.Metadata{GenesisSHA256: "abc123", GnolandVersion: "v1.0.1"}

	genesisMatch, versionSupported := MetadataChecks(meta, cfg)
	if !genesisMatch {
		t.Error("genesisMatch = false, want true")
	}
	if !versionSupported {
		t.Error("versionSupported = false, want true")
	}
}

func TestMetadataChecks_GenesisAndVersionMismatch(t *testing.T) {
	cfg := windowTestConfig()
	meta := submission.Metadata{GenesisSHA256: "wrong-hash", GnolandVersion: "v9.9.9"}

	genesisMatch, versionSupported := MetadataChecks(meta, cfg)
	if genesisMatch {
		t.Error("genesisMatch = true, want false")
	}
	if versionSupported {
		t.Error("versionSupported = true, want false")
	}
}

func TestMetadataChecks_GenesisAndVersionToleratePresentation(t *testing.T) {
	// sha256sum emits lowercase, but a hash pasted from a block explorer,
	// a wiki table or Windows CertUtil is commonly uppercase, and form
	// fields collect stray whitespace. A hash is the same hash either
	// way; a case difference in the config would otherwise turn every
	// submission into a genesis-mismatch warning, with nothing pointing
	// at the config as the cause.
	cfg := windowTestConfig()
	cfg.ExpectedGenesisSHA256 = "  ABC123  "
	cfg.SupportedGnolandVersions = []string{" v1.0.0 ", "v1.0.1"}

	meta := submission.Metadata{GenesisSHA256: "abc123", GnolandVersion: "v1.0.0"}
	genesisMatch, versionSupported := MetadataChecks(meta, cfg)
	if !genesisMatch {
		t.Error("genesisMatch = false, want true: the same hash in a different case is the same hash")
	}
	if !versionSupported {
		t.Error("versionSupported = false, want true: a padded config entry is the same version")
	}
}

func TestScanLogWindow_FullyCovered(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T17:00:00Z starting up",
		"2026-07-08T20:00:00Z consensus running",
		"2026-07-09T19:00:00Z shutting down",
	)

	window := ScanLogWindow(logGz, cfg)
	if !window.Detected || !window.Covered {
		t.Errorf("window = %+v, want Detected and Covered", window)
	}
}

func TestScanLogWindow_StartsAfterWindowOpened(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T19:00:00Z starting up",
		"2026-07-08T20:00:00Z consensus running",
	)

	window := ScanLogWindow(logGz, cfg)
	if !window.Detected {
		t.Error("window.Detected = false, want true")
	}
	if window.Covered {
		t.Error("window.Covered = true, want false (the log begins after the investigation window opened)")
	}
}

func TestScanLogWindow_EndsBeforeWindowClosed(t *testing.T) {
	// The start side is fine and only the end side fails. Without this
	// case the end-side half of the coverage check is dead weight: a
	// start-side-only implementation passes every other test in the repo.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T17:00:00Z starting up before the window opened",
		"2026-07-09T10:00:00Z stopped well before the window closed",
	)

	window := ScanLogWindow(logGz, cfg)
	if !window.Detected {
		t.Error("window.Detected = false, want true")
	}
	if window.Covered {
		t.Error("window.Covered = true, want false (the log ends before the investigation window closed)")
	}
}

func TestScanLogWindow_TruncatedIsNotTreatedAsCovered(t *testing.T) {
	// A log whose real timestamps span one second, padded past the scan
	// budget. It says nothing about covering a 24-hour window, so it must
	// not score as if it did: an unverified tail is not a verified one.
	cfg := windowTestConfig()

	const budget = 64 << 10
	lines := []string{"2026-07-08T17:00:00Z starting up"}
	filler := "2026-07-08T17:00:01Z " + strings.Repeat("x", 200)
	for len(lines)*len(filler) < budget*2 {
		lines = append(lines, filler)
	}
	lines = append(lines, "2026-07-09T19:00:00Z shutting down") // past the budget, never read
	logGz := gzipLines(t, lines...)

	window := scanLogWindow(logGz, cfg, budget)
	if !window.Truncated {
		t.Fatalf("window = %+v, want Truncated (the budget, not the log, ended the scan)", window)
	}
	if !window.Detected {
		t.Error("window.Detected = false, want true")
	}
	if window.Covered {
		t.Error("window.Covered = true, want false: the tail was never read, so coverage was never verified")
	}
	if got := LogQualityScore(window, LogWindowCheck{}); got != 17 {
		t.Errorf("LogQualityScore = %d, want 17 (partial credit — detected but unverified, neither full marks nor a penalty)", got)
	}
}

func TestScanLogWindow_OverlongLineMarksTruncated(t *testing.T) {
	// bufio.Scanner gives up on a line past its buffer cap. That ends the
	// scan for our reasons, not the submitter's, so it has to raise the
	// same "unverified" signal the byte budget does — otherwise the
	// generated summary states as fact that a validator's logs miss the
	// window, when all that happened is our buffer overflowed.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T17:00:00Z starting up before the window opened",
		strings.Repeat("x", maxLogLineBytes+1), // e.g. a panic dump
		"2026-07-09T19:00:00Z ran past the end of the window",
	)

	window := scanLogWindow(logGz, cfg, maxLogWindowBytes)
	if !window.Truncated {
		t.Fatalf("window = %+v, want Truncated (an over-long line ended the scan early)", window)
	}
	if window.Covered {
		t.Error("window.Covered = true, want false: the scan never reached the closing timestamp")
	}
}

func TestScanLogWindow_UsesEarliestAndLatestTimestamps(t *testing.T) {
	// Rotated log files concatenated out of order, or interleaved
	// goroutine output, break the assumption that the first line carries
	// the earliest timestamp and the last line the latest.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-09T19:00:00Z this line is last chronologically but comes first",
		"2026-07-08T17:00:00Z and this one is earliest but comes last",
	)

	window := scanLogWindow(logGz, cfg, maxLogWindowBytes)
	if want := time.Date(2026, 7, 8, 17, 0, 0, 0, time.UTC); !window.FirstSeen.Equal(want) {
		t.Errorf("FirstSeen = %v, want %v (the earliest timestamp, not the first line)", window.FirstSeen, want)
	}
	if want := time.Date(2026, 7, 9, 19, 0, 0, 0, time.UTC); !window.LastSeen.Equal(want) {
		t.Errorf("LastSeen = %v, want %v (the latest timestamp, not the last line)", window.LastSeen, want)
	}
	if !window.Covered {
		t.Error("window.Covered = false, want true: the timestamps present do span the window")
	}
}

func TestScanLogWindow_BudgetBoundsDecompression(t *testing.T) {
	// The bomb defence: validator.log.gz's content is itself compressed
	// plaintext that ValidateArchive never decompresses, so this is the
	// first place decompression happens and the budget is what keeps a
	// small upload from expanding without limit.
	cfg := windowTestConfig()

	const budget = 64 << 10
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	line := []byte("2026-07-08T17:00:00Z " + strings.Repeat("x", 200) + "\n")
	for i := 0; i < 100*budget/len(line); i++ {
		if _, err := gw.Write(line); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	window := scanLogWindow(&buf, cfg, budget)
	if !window.Truncated {
		t.Errorf("window = %+v, want Truncated: the scan must stop at its budget rather than decompress the whole stream", window)
	}
}

func TestScanLogWindow_NotTruncatedWhenUnderCap(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t, "2026-07-08T17:00:00Z starting up", "2026-07-09T19:00:00Z shutting down")

	window := ScanLogWindow(logGz, cfg)
	if window.Truncated {
		t.Errorf("window = %+v, want Truncated = false for a log well under the cap", window)
	}
}

func TestScanLogWindow_NoTimestamps(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t, "no timestamp here", "nor here either")

	window := ScanLogWindow(logGz, cfg)
	if window.Detected {
		t.Errorf("window = %+v, want !Detected", window)
	}
}

func TestScanLogWindow_DetectsJSONEpochTimestamps(t *testing.T) {
	// gnoland's actual logger (cometbft/tendermint-style) emits structured
	// JSON lines with a "ts" field holding a Unix epoch float, not a
	// leading RFC3339 string — e.g.
	// {"level":"info","ts":1783659600.5,"msg":"starting up"}. Real
	// submissions use this format, so the log-quality check has to
	// understand it too, not just the plain-text fixture format the other
	// tests use.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		// 2026-07-08T17:00:00.5Z, before the window opens
		`{"level":"info","ts":1783530000.5,"msg":"starting up","module":"main"}`,
		// 2026-07-08T20:00:00.25Z, mid-window
		`{"level":"info","ts":1783540800.25,"msg":"consensus running","module":"consensus"}`,
		// 2026-07-09T19:00:00Z, after the window closes — no fractional
		// part, since a real logger doesn't always emit one
		`{"level":"info","ts":1783623600,"msg":"shutting down","module":"main"}`,
	)

	window := ScanLogWindow(logGz, cfg)
	if !window.Detected {
		t.Fatalf("window = %+v, want Detected (JSON \"ts\" epoch timestamps should be recognized)", window)
	}
	if !window.Covered {
		t.Errorf("window = %+v, want Covered", window)
	}

	wantFirst := time.Date(2026, 7, 8, 17, 0, 0, 500000000, time.UTC)
	if !window.FirstSeen.Equal(wantFirst) {
		t.Errorf("FirstSeen = %v, want %v", window.FirstSeen, wantFirst)
	}
	wantLast := time.Date(2026, 7, 9, 19, 0, 0, 0, time.UTC)
	if !window.LastSeen.Equal(wantLast) {
		t.Errorf("LastSeen = %v, want %v", window.LastSeen, wantLast)
	}
}

func TestScanLogWindow_IgnoresJSONLinesWithoutTs(t *testing.T) {
	// A JSON line missing "ts" (or with a non-numeric one) must be
	// skipped like any other unparseable line, not treated as a zero
	// timestamp — that would silently drag FirstSeen back to the Unix
	// epoch.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		`{"level":"info","msg":"no ts field here"}`,
		`{"level":"info","ts":"not-a-number","msg":"ts is a string"}`,
		`not json at all`,
	)

	window := ScanLogWindow(logGz, cfg)
	if window.Detected {
		t.Errorf("window = %+v, want !Detected", window)
	}
}

func TestScanLogWindow_LogNotGzip(t *testing.T) {
	cfg := windowTestConfig()

	window := ScanLogWindow(strings.NewReader("not gzip at all"), cfg)
	if window.Detected || window.Covered {
		t.Errorf("window = %+v, want the zero value for unparseable input", window)
	}
}

func TestScanLogWindow_DetectsTimestampAfterSyslogPrefix(t *testing.T) {
	// journalctl's default output ("-o short") prefixes every line with a
	// syslog-style "Jul  8 18:00:00 host unit[pid]:" stamp, which carries
	// no year and no zone. The timestamp worth reading is gnoland's own,
	// further along the line — and journald escapes the tab that follows
	// it as a literal "#011", so it is not whitespace-delimited either.
	// Looking only at the first field finds neither.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		`Jul  8 18:00:00 SERVER1 gnoland[188026]: 2026-07-08T17:59:59.998Z#011#033[34mINFO #033[0m#011starting up`,
		`Jul  9 18:30:00 SERVER1 gnoland[188026]: 2026-07-09T18:30:00.100Z#011#033[34mINFO #033[0m#011shutting down`,
	)

	window := ScanLogWindow(logGz, cfg)
	if !window.Detected {
		t.Fatalf("window = %+v, want Detected", window)
	}
	if !window.Covered {
		t.Errorf("window = %+v, want Covered", window)
	}
	wantFirst := time.Date(2026, 7, 8, 17, 59, 59, 998000000, time.UTC)
	if !window.FirstSeen.Equal(wantFirst) {
		t.Errorf("FirstSeen = %v, want %v", window.FirstSeen, wantFirst)
	}
}

func TestScanLogWindow_DetectsNumericZoneOffset(t *testing.T) {
	// "journalctl -o short-iso" and gnoland's own console encoder render
	// the zone as "+0200", without the colon RFC3339 requires. Same
	// instant, different spelling.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T19:59:59.998+0200\tINFO\tstarting up",
		"2026-07-09T20:30:00.100+0200\tINFO\tshutting down",
	)

	window := ScanLogWindow(logGz, cfg)
	if !window.Detected {
		t.Fatalf("window = %+v, want Detected", window)
	}
	if !window.Covered {
		t.Errorf("window = %+v, want Covered", window)
	}
	wantFirst := time.Date(2026, 7, 8, 17, 59, 59, 998000000, time.UTC)
	if !window.FirstSeen.Equal(wantFirst.In(window.FirstSeen.Location())) {
		t.Errorf("FirstSeen = %v, want %v", window.FirstSeen, wantFirst)
	}
}

func TestScanLogWindow_ToleratesWindowEdgeJitter(t *testing.T) {
	// A validator who runs `journalctl --since <start> --until <end>` gets
	// the first entry at or after the start and the last one strictly
	// before the end — never the boundary instants themselves. Judging
	// coverage to the nanosecond fails that submission for sub-second
	// gaps it could not have avoided, which is not what the criterion is
	// asking about.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T18:00:00.322Z first entry journalctl returned",
		"2026-07-09T18:29:59.999Z last entry journalctl returned",
	)

	window := ScanLogWindow(logGz, cfg)
	if !window.Detected {
		t.Fatalf("window = %+v, want Detected", window)
	}
	if !window.Covered {
		t.Errorf("window = %+v, want Covered: both edges are inside the grace period", window)
	}
}

func TestScanLogWindow_DoesNotExtendToleranceBeyondGrace(t *testing.T) {
	// The grace absorbs boundary semantics, not a genuinely short log.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T18:05:00Z started five minutes into the window",
		"2026-07-09T18:30:00Z ran to the end",
	)

	window := ScanLogWindow(logGz, cfg)
	if !window.Detected {
		t.Fatalf("window = %+v, want Detected", window)
	}
	if window.Covered {
		t.Errorf("window = %+v, want !Covered: five minutes is well past the grace period", window)
	}
}

// TestParseLeadingTimestamp_CollectorFormats pins the line shapes that
// actually reached the portal in the 2026-09-02 drill. Almost no
// submission carried a raw gnoland log: validators exported through
// journalctl, whose output format varies by flag and by locale, and each
// variant hides the timestamp somewhere different.
func TestParseLeadingTimestamp_CollectorFormats(t *testing.T) {
	tests := []struct {
		name string
		line string
		want time.Time
	}{{
		name: "journalctl -o short",
		line: `Sep  1 12:00:00 SERVER1 gnoland[188026]: 2026-09-01T12:00:00.322Z#011#033[34mINFO #033[0m#011Ignoring inbound connection`,
		want: time.Date(2026, 9, 1, 12, 0, 0, 322000000, time.UTC),
	}, {
		name: "journalctl -o short, zero-padded day, offset zone",
		line: `Sep 01 14:00:00 fr.ovh.server4 gnoland[533073]: 2026-09-01T14:00:00.363+0200        WARN         ignoring dial request`,
		want: time.Date(2026, 9, 1, 12, 0, 0, 363000000, time.UTC),
	}, {
		// The syslog prefix is rendered in the host's locale. Reading it
		// would mean parsing month names in every language; the embedded
		// gnoland timestamp is locale-independent.
		name: "journalctl -o short, French locale",
		line: `sept. 02 19:03:10 Nomic gnoland[3032008]: 2026-09-02T21:03:10.132+0200        INFO         Timed out`,
		want: time.Date(2026, 9, 2, 19, 3, 10, 132000000, time.UTC),
	}, {
		name: "journalctl -o short-iso-precise",
		line: `2026-09-01T12:00:00.279610+00:00 n5fe5e7 gnoland-pearl[2051606]: 2026-09-01T12:00:00.279Z#011#033[34mINFO #033[0m#011Ignoring inbound`,
		want: time.Date(2026, 9, 1, 12, 0, 0, 279610000, time.UTC),
	}, {
		name: "journalctl -o short-iso",
		line: `2026-09-03T10:00:09+0200 mail.nodesync.top gnoland[2359539]: Suppressed 3359 messages`,
		want: time.Date(2026, 9, 3, 8, 0, 9, 0, time.UTC),
	}, {
		name: "gnoland console encoder, offset zone",
		line: "2026-09-01T14:00:00.186+0200\tINFO \tStarting Peer\t{\"module\": \"p2p\"}",
		want: time.Date(2026, 9, 1, 12, 0, 0, 186000000, time.UTC),
	}, {
		name: "gnoland console encoder, UTC",
		line: "2026-09-02T20:52:09.642Z\tDEBUG\taddVote\t{\"module\": \"consensus\"}",
		want: time.Date(2026, 9, 2, 20, 52, 9, 642000000, time.UTC),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, ok := parseLeadingTimestamp(tt.line)
			if !ok {
				t.Fatalf("parseLeadingTimestamp(%q) = _, false; want a timestamp", tt.line)
			}
			if !ts.Equal(tt.want) {
				t.Errorf("parseLeadingTimestamp() = %v, want %v", ts.UTC(), tt.want)
			}
		})
	}
}

func TestParseLeadingTimestamp_SkipsStackTraceContinuation(t *testing.T) {
	// A panic or error dump continues across lines that carry a collector
	// prefix but no timestamp of their own. Nothing in them is a time,
	// and inventing one from the syslog prefix — which has no year —
	// would drag FirstSeen back to year zero.
	line := `sept. 02 05:16:55 Nomic gnoland[3032008]: github.com/gnolang/gno/tm2/pkg/p2p.(*MultiplexSwitch).Broadcast.func1`
	if ts, ok := parseLeadingTimestamp(line); ok {
		t.Errorf("parseLeadingTimestamp() = %v, true; want false", ts)
	}
}

// BenchmarkParseLeadingTimestamp measures the two paths separately: the
// first-field fast path, and the fallback that searches the head of the
// line. The fallback runs on every line of a journald-collected log, and
// those run to gigabytes decompressed, so its cost bounds how long a
// scan takes and therefore how much of maxLogWindowBytes is usable.
func BenchmarkParseLeadingTimestamp(b *testing.B) {
	benchmarks := []struct {
		name string
		line string
	}{
		{"fast path", "2026-09-01T12:00:00.279610+00:00 n5fe5e7 gnoland-pearl[2051606]: Ignoring inbound connection"},
		{"regex fallback", `Sep  1 12:00:00 SERVER1 gnoland[188026]: 2026-09-01T12:00:00.322Z#011#033[34mINFO #033[0m#011Ignoring inbound connection`},
		{"no timestamp", `Sep  1 12:00:00 Nomic gnoland[3032008]: github.com/gnolang/gno/tm2/pkg/p2p.(*MultiplexSwitch).Broadcast.func1`},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			for range b.N {
				parseLeadingTimestamp(bm.line)
			}
		})
	}
}

func TestScanLogWindow_SeparatesAnEmptyLogFromAnUnparseableOne(t *testing.T) {
	// Both score zero, but they are different failures: one validator
	// uploaded nothing, the other uploaded something this could not read.
	// ScannedBytes is what lets the generated summary say which.
	cfg := windowTestConfig()

	empty := ScanLogWindow(gzipLines(t), cfg)
	if empty.Detected {
		t.Errorf("empty = %+v, want !Detected", empty)
	}
	if empty.ScannedBytes != 0 {
		t.Errorf("empty.ScannedBytes = %d, want 0", empty.ScannedBytes)
	}

	unparseable := ScanLogWindow(gzipLines(t, "no timestamp here", "nor here either"), cfg)
	if unparseable.Detected {
		t.Errorf("unparseable = %+v, want !Detected", unparseable)
	}
	if unparseable.ScannedBytes == 0 {
		t.Error("unparseable.ScannedBytes = 0, want the bytes it read: the log had content, it just held no timestamp")
	}
}
