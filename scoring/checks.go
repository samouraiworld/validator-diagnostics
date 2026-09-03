package scoring

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/submission"
)

// maxLogWindowBytes bounds how much *decompressed* plaintext scanLogWindow
// will read out of one submitted log, independent of the compressed-size cap
// submission.ValidateArchive enforces and submission.ScanLogs re-applies, and
// independent of the antivirus's own decompressed budget
// (clamav.DefaultScanBudget, 32 GiB, shared across both logs). Two budgets
// over the same bytes, for unrelated reasons: exceeding this one costs
// partial credit via LogWindowCheck.Truncated, exceeding the antivirus's
// costs coverage.
//
// It is set well above a plausible validator log rather than at the
// smallest workable value, because the budget running out is not a free
// outcome: the end of the log is what proves investigation-window
// coverage, and a scan that stops early can only report the coverage as
// unverified (see LogWindowCheck.Truncated). Nothing is retained as it
// scans, so the cost of a large budget is decompression time, not
// memory.
//
// It was 1 GiB until the 2026-09-02 drill, where two submissions
// decompressed past it — one to 1.39 GB, one to 2.27 GB — and one of
// those was the only submission in the field that covered the window
// end to end. "A plausible validator log" for a busy node over a
// two-hour window is larger than that first guess, so this now matches
// cmd/portal's own per-entry ceiling: the scan is willing to read
// whatever the upload was accepted with.
const maxLogWindowBytes = 4 << 30 // 4 GiB of plaintext

// maxLogLineBytes caps a single buffered line. A line longer than this
// ends the scan (bufio.ErrTooLong), which counts as truncation for the
// same reason the byte budget does.
const maxLogLineBytes = 1 << 20

// timestampLayouts are tried, in order, against a candidate timestamp
// lifted out of a log line. The two "-0700" spellings are not
// redundant with RFC3339: that layout demands a colon in the zone
// offset, and both "journalctl -o short-iso" and gnoland's own console
// encoder render it without one ("+0200").
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999-0700",
	"2006-01-02T15:04:05-0700",
}

// timestampRe locates an ISO 8601 date-time carrying an explicit zone
// anywhere in a log line, which is what makes a line collected through
// journald readable. "journalctl -o short" — the default, and what most
// submissions to the 2026-09-02 drill used — prefixes every line with a
// syslog stamp ("Sep  1 12:00:00 host gnoland[188026]: ") that has
// neither a year nor a zone, and journald escapes the tab after
// gnoland's own timestamp as a literal "#011", so the real timestamp is
// neither the first field nor whitespace-delimited.
//
// An explicit zone is required rather than assumed: submissions arrive
// from hosts running at every offset, and reading a naive local time as
// UTC would shift a perfectly good log by hours — a worse failure than
// not recognizing it, because it is silent.
var timestampRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})`)

// timestampSearchBytes bounds how far into a line timestampRe looks. Every
// collector prefix observed in practice (syslog, docker-compose, kubectl)
// costs a few dozen bytes, so this is generous; the point is that a line
// may be up to maxLogLineBytes long and scanning all of it, on every line
// of a multi-gigabyte log, would cost far more than it could ever find.
// A timestamp straddling the cutoff is missed on that line alone, which
// changes nothing: coverage is the earliest and latest over every line.
const timestampSearchBytes = 256

// windowGrace is how far outside the configured investigation window a
// log's first and last timestamps may fall and still count as covering
// it.
//
// Without it the check is exact to the nanosecond, which no validator
// can satisfy: `journalctl --since <start> --until <end>` returns the
// first entry at or after the start and the last one strictly before the
// end, so the boundary instants themselves are never present. In the
// 2026-09-02 drill that failed 22 submissions holding exactly the
// requested window, one of them by 293 microseconds. A minute is far
// below the resolution the criterion is actually asking about — whether
// the validator captured the right two hours — while still failing a log
// that genuinely starts late.
const windowGrace = time.Minute

// MetadataChecks runs prd.md's Phase 3 metadata checks for one
// submission: genesis hash and supported gnoland version.
//
// This and ScanLogWindow were one function (AutoChecks) until the
// archive grew a second log. A single walk of the tar cannot hand two
// entry readers to one function at once — the readers are only valid
// one at a time — so the caller drives submission.ScanLogs and calls
// ScanLogWindow per entry instead.
func MetadataChecks(meta submission.Metadata, cfg exercise.Config) (genesisMatch, versionSupported bool) {
	// Compared on content, not presentation. A hash is the same hash in
	// either case — sha256sum emits lowercase, a block explorer or
	// Windows CertUtil commonly uppercase — and form fields collect stray
	// whitespace. A byte-exact comparison would turn a config pasted from
	// the wrong source into a genesis mismatch reported against every
	// validator, with nothing to suggest the config is the problem.
	genesisMatch = strings.EqualFold(strings.TrimSpace(meta.GenesisSHA256), strings.TrimSpace(cfg.ExpectedGenesisSHA256))

	version := strings.TrimSpace(meta.GnolandVersion)
	for _, v := range cfg.SupportedGnolandVersions {
		if strings.TrimSpace(v) == version {
			versionSupported = true
			break
		}
	}

	return genesisMatch, versionSupported
}

// ScanLogWindow scans one submitted log for timestamps covering the
// exercise's investigation window. logGz must be an entry stream handed
// out by submission.ScanLogs — the same archive entry ValidateArchive
// already accepted, read straight out of the upload and never buffered
// — and never a second, independent read of the raw upload (see this
// repo's Phase 3 design spec, "Security").
func ScanLogWindow(logGz io.Reader, cfg exercise.Config) LogWindowCheck {
	return scanLogWindow(logGz, cfg, maxLogWindowBytes)
}

// scanLogWindow decompresses logGz under a reader bounded to budget
// decompressed bytes and looks for a recognizable timestamp at the start
// of each line, best-effort: an unparseable or non-gzip input simply
// yields the zero LogWindowCheck rather than an error, since gnoland's
// exact log format isn't part of prd.md's contract. budget is a
// parameter rather than a constant so tests can exercise the truncation
// path without generating maxLogWindowBytes of input.
func scanLogWindow(logGz io.Reader, cfg exercise.Config, budget int64) LogWindowCheck {
	gz, err := gzip.NewReader(logGz)
	if err != nil {
		return LogWindowCheck{}
	}
	defer gz.Close()

	bounded := &io.LimitedReader{R: gz, N: budget}
	scanner := bufio.NewScanner(bounded)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogLineBytes)

	var first, last time.Time
	var detected bool

	for scanner.Scan() {
		ts, ok := parseLeadingTimestamp(scanner.Text())
		if !ok {
			continue
		}
		// Earliest and latest, not first line and last line: rotated logs
		// concatenated out of order and interleaved goroutine output both
		// break the monotonicity that assumption would need.
		if !detected || ts.Before(first) {
			first = ts
		}
		if !detected || ts.After(last) {
			last = ts
		}
		detected = true
	}

	// Either way the scan stopped for our reasons rather than because the
	// log ended, so everything past that point is unread. Reading the
	// scanner error matters as much as the byte budget: a single
	// over-long line (a panic dump, a large embedded payload) hits
	// bufio.ErrTooLong with budget to spare, and treating that as a
	// complete scan would let our own buffer limit be reported as the
	// validator's logs falling short of the window.
	scanned := budget - bounded.N
	truncated := scanner.Err() != nil || scanHitCap(bounded, gz)

	if !detected {
		return LogWindowCheck{Truncated: truncated, ScannedBytes: scanned}
	}

	// Coverage means verified coverage, on both sides. A truncated scan
	// never reached the end of the log, so it cannot establish the end
	// side — it yields partial credit via LogQualityScore and an
	// explicitly informational note in the generated summary, rather than
	// either full marks it didn't earn or a warning it didn't deserve.
	covered := !first.After(cfg.InvestigationWindowStart.Add(windowGrace)) &&
		!last.Before(cfg.InvestigationWindowEnd.Add(-windowGrace))
	return LogWindowCheck{Detected: true, Covered: covered, Truncated: truncated, FirstSeen: first, LastSeen: last, ScannedBytes: scanned}
}

// scanHitCap reports whether bounded ran out of budget with data still
// waiting in gz — i.e. the cap ended the scan rather than the log ending
// on its own. If any budget is left the underlying stream was drained,
// so there is nothing to probe for.
func scanHitCap(bounded *io.LimitedReader, gz io.Reader) bool {
	if bounded.N > 0 {
		return false
	}
	var probe [1]byte
	n, _ := io.ReadFull(gz, probe[:])
	return n > 0
}

// parseLeadingTimestamp recovers the instant a log line describes, in
// three passes, cheapest first.
//
// The first tries timestampLayouts against the first whitespace-delimited
// token — splitting on whitespace first (rather than taking a
// fixed-length prefix) is what lets this correctly handle layouts whose
// rendered width varies (e.g. "Z" vs "+02:00"). That covers a raw
// gnoland log and anything collected with "journalctl -o short-iso*", and
// costs no allocation.
//
// The second searches the head of the line for an embedded timestamp,
// which is where journald's default output and every other collector
// prefix leaves it. It only runs when the first pass found nothing, so
// logs in the common shapes never pay for it.
//
// The third is parseJSONTimestamp, for gnoland's structured output, which
// is a JSON object with no plain-text timestamp at all.
func parseLeadingTimestamp(line string) (time.Time, bool) {
	field := line
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		field = line[:i]
	}
	if len(field) > 0 && len(field) <= 64 {
		if ts, ok := parseTimestampField(field); ok {
			return ts, true
		}
	}

	head := line
	if len(head) > timestampSearchBytes {
		head = head[:timestampSearchBytes]
	}
	// indexTimestamp first, timestampRe second. The regexp is the
	// authority on what a timestamp is, but running it on every line of a
	// journald-collected log costs about ten times what the byte scan
	// does, and most lines that reach here hold no timestamp at all —
	// stack-trace continuations, journald's own notices. The cheap scan
	// rejects those outright.
	if i := indexTimestamp(head); i >= 0 {
		if m := timestampRe.FindString(head[i:]); m != "" {
			if ts, ok := parseTimestampField(m); ok {
				return ts, true
			}
		}
	}

	return parseJSONTimestamp(line)
}

// indexTimestamp returns the offset of the first position in s that could
// begin an ISO 8601 date-time — four leading digits, dashes in the right
// places, a "T" at offset 10 — or -1 if there is none.
//
// It is deliberately weaker than timestampRe: a false positive only costs
// the caller a regexp run that starts earlier than it had to, and since
// that run scans forward it still finds any real timestamp further along
// the line. A false negative would lose the line entirely, so the checks
// here are the ones every accepted spelling shares.
func indexTimestamp(s string) int {
	for off := 0; ; {
		j := strings.IndexByte(s[off:], 'T')
		if j < 0 {
			return -1
		}
		i := off + j
		if i >= 10 && s[i-4] >= '0' && s[i-4] <= '9' && s[i-6] == '-' && s[i-3] == '-' && s[i-10] >= '0' && s[i-10] <= '9' {
			return i - 10
		}
		off = i + 1
	}
}

// parseTimestampField tries each of timestampLayouts against one
// already-isolated candidate.
func parseTimestampField(field string) (time.Time, bool) {
	for _, layout := range timestampLayouts {
		if ts, err := time.Parse(layout, field); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

// jsonLogLine is the subset of gnoland's (cometbft/tendermint-style)
// structured log line this cares about: a top-level "ts" field holding
// a Unix epoch, seconds as a JSON number — usually with a fractional
// part for sub-second precision, but not always, so this must accept
// both "1783530000.5" and "1783530000".
type jsonLogLine struct {
	Ts json.Number `json:"ts"`
}

// parseJSONTimestamp decodes line as a single JSON object and reads its
// "ts" field, best-effort like parseLeadingTimestamp's caller expects:
// a line that isn't JSON, or has no numeric "ts", simply isn't a
// timestamp rather than an error.
func parseJSONTimestamp(line string) (time.Time, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") {
		return time.Time{}, false
	}

	var v jsonLogLine
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil || v.Ts == "" {
		return time.Time{}, false
	}
	epoch, err := v.Ts.Float64()
	if err != nil {
		return time.Time{}, false
	}

	sec := int64(epoch)
	nsec := int64((epoch - float64(sec)) * float64(time.Second))
	return time.Unix(sec, nsec).UTC(), true
}
