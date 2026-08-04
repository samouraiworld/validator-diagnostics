package scoring

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/submission"
)

// maxLogScanBytes bounds how much *decompressed* plaintext scanLogWindow
// will read out of gnoland.log.gz, independent of the compressed-size
// cap submission.ValidateArchive already applied to logGz. This is the
// inner-layer equivalent of prd.md's "decompressed-size limit,
// independent from the compressed upload size limit": gnoland.log.gz's
// own content is itself gzip-compressed plaintext that ValidateArchive
// never decompresses, so this is the first place that decompression
// happens, and it needs its own bomb protection.
const maxLogScanBytes = 8 << 20 // 8 MiB of plaintext is far more than needed to find a first/last timestamp

// timestampLayouts are tried, in order, against the first
// whitespace-delimited token of each log line.
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
}

// AutoChecks runs prd.md's Phase 3 "Automatic validation" checks for
// one submission: genesis hash, supported gnoland version, and
// investigation-window coverage of the submitted log. logGz must be
// submission.Result.LogGz — the same bounded bytes ValidateArchive
// already read — never a second, independent read of the raw upload
// (see this repo's Phase 3 design spec, "Security").
func AutoChecks(meta submission.Metadata, logGz []byte, cfg exercise.Config) (genesisMatch, versionSupported bool, window LogWindowCheck) {
	genesisMatch = meta.GenesisSHA256 == cfg.ExpectedGenesisSHA256

	for _, v := range cfg.SupportedGnolandVersions {
		if v == meta.GnolandVersion {
			versionSupported = true
			break
		}
	}

	window = scanLogWindow(logGz, cfg)
	return genesisMatch, versionSupported, window
}

// scanLogWindow decompresses logGz under its own bounded reader and
// looks for a recognizable timestamp at the start of each line,
// best-effort: an unparseable or non-gzip input simply yields the zero
// LogWindowCheck rather than an error, since gnoland's exact log format
// isn't part of prd.md's contract.
func scanLogWindow(logGz []byte, cfg exercise.Config) LogWindowCheck {
	gz, err := gzip.NewReader(bytes.NewReader(logGz))
	if err != nil {
		return LogWindowCheck{}
	}
	defer gz.Close()

	bounded := &io.LimitedReader{R: gz, N: maxLogScanBytes}
	scanner := bufio.NewScanner(bounded)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20) // cap a single buffered line at 1 MiB

	var first, last time.Time
	var detected bool

	for scanner.Scan() {
		ts, ok := parseLeadingTimestamp(scanner.Text())
		if !ok {
			continue
		}
		if !detected {
			first = ts
			detected = true
		}
		last = ts
	}
	// scanner.Err() (e.g. ErrTooLong on a pathological line) just means
	// scanning stopped early — whatever was found before that point is
	// still returned, consistent with this being a best-effort check.

	truncated := scanHitCap(bounded, gz)

	if !detected {
		return LogWindowCheck{Truncated: truncated}
	}

	// A real validator log easily exceeds maxLogScanBytes decompressed,
	// and the cap is ours, not the submitter's fault: when it is what
	// ended the scan, `last` is simply the last timestamp we bothered to
	// read and says nothing about whether the log runs to the end of the
	// investigation window. Judge coverage on the start side only in that
	// case — otherwise virtually every genuine submission would be marked
	// as not covering the window and lose log-quality points for it.
	covered := !first.After(cfg.InvestigationWindowStart)
	if !truncated {
		covered = covered && !last.Before(cfg.InvestigationWindowEnd)
	}
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
// (e.g. "Z" vs "+02:00").
func parseLeadingTimestamp(line string) (time.Time, bool) {
	field := line
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		field = line[:i]
	}
	if len(field) == 0 || len(field) > 64 {
		return time.Time{}, false
	}
	for _, layout := range timestampLayouts {
		if ts, err := time.Parse(layout, field); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}
