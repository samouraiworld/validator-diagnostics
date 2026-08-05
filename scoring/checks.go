package scoring

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/submission"
)

// maxLogScanBytes bounds how much *decompressed* plaintext scanLogWindow
// will read out of gnoland.log.gz, independent of the compressed-size
// cap submission.ValidateArchive enforces and submission.OpenLog re-applies.
// This is the inner-layer equivalent of prd.md's "decompressed-size limit,
// independent from the compressed upload size limit": gnoland.log.gz's
// own content is itself gzip-compressed plaintext that ValidateArchive
// never decompresses, so this is the first place that decompression
// happens, and it needs its own bomb protection.
//
// It is set well above a plausible validator log rather than at the
// smallest workable value, because the budget running out is not a free
// outcome: the end of the log is what proves investigation-window
// coverage, and a scan that stops early can only report the coverage as
// unverified (see LogWindowCheck.Truncated). Nothing is retained as it
// scans, so the cost of a large budget is decompression time, not
// memory.
const maxLogScanBytes = 1 << 30 // 1 GiB of plaintext

// maxLogLineBytes caps a single buffered line. A line longer than this
// ends the scan (bufio.ErrTooLong), which counts as truncation for the
// same reason the byte budget does.
const maxLogLineBytes = 1 << 20

// timestampLayouts are tried, in order, against the first
// whitespace-delimited token of each log line.
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
}

// AutoChecks runs prd.md's Phase 3 "Automatic validation" checks for one
// submission: genesis hash, supported gnoland version, and
// investigation-window coverage of the submitted log. logGz must be the
// stream returned by submission.OpenLog — the same archive entry
// ValidateArchive already accepted, read straight out of the upload and
// never buffered — and never a second, independent read of the raw upload
// (see this repo's Phase 3 design spec, "Security").
func AutoChecks(meta submission.Metadata, logGz io.Reader, cfg exercise.Config) (genesisMatch, versionSupported bool, window LogWindowCheck) {
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

	window = scanLogWindow(logGz, cfg, maxLogScanBytes)
	return genesisMatch, versionSupported, window
}

// scanLogWindow decompresses logGz under a reader bounded to budget
// decompressed bytes and looks for a recognizable timestamp at the start
// of each line, best-effort: an unparseable or non-gzip input simply
// yields the zero LogWindowCheck rather than an error, since gnoland's
// exact log format isn't part of prd.md's contract. budget is a
// parameter rather than a constant so tests can exercise the truncation
// path without generating maxLogScanBytes of input.
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
	truncated := scanner.Err() != nil || scanHitCap(bounded, gz)

	if !detected {
		return LogWindowCheck{Truncated: truncated}
	}

	// Coverage means verified coverage, on both sides. A truncated scan
	// never reached the end of the log, so it cannot establish the end
	// side — it yields partial credit via LogQualityScore and an
	// explicitly informational note in the generated summary, rather than
	// either full marks it didn't earn or a warning it didn't deserve.
	covered := !first.After(cfg.InvestigationWindowStart) && !last.Before(cfg.InvestigationWindowEnd)
	return LogWindowCheck{Detected: true, Covered: covered, Truncated: truncated, FirstSeen: first, LastSeen: last}
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

// parseLeadingTimestamp tries each of timestampLayouts against the
// first whitespace-delimited token of line — splitting on whitespace
// first (rather than taking a fixed-length prefix) is what lets this
// correctly handle layouts like RFC3339 whose rendered width varies
// (e.g. "Z" vs "+02:00"). Falls back to parseJSONTimestamp for
// gnoland's actual logger output, which is a JSON object rather than a
// leading plain-text timestamp.
func parseLeadingTimestamp(line string) (time.Time, bool) {
	field := line
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		field = line[:i]
	}
	if len(field) > 0 && len(field) <= 64 {
		for _, layout := range timestampLayouts {
			if ts, err := time.Parse(layout, field); err == nil {
				return ts, true
			}
		}
	}
	return parseJSONTimestamp(line)
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
