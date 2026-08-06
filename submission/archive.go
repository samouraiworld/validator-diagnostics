package submission

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
)

const (
	ValidatorLogFileName = "validator.log.gz"
	SentryLogFileName    = "sentry.log.gz"
	MetadataFileName     = "metadata.json"

	defaultMaxLogSize      = 2 << 30 // 2 GiB
	defaultMaxMetadataSize = 64 << 10
)

// allowedEntries is what may appear in an archive; requiredEntries is
// what must. They were one map until sentry.log.gz — the first entry
// that is accepted without being demanded — made the two sets differ.
// requiredEntries is a slice, not a map, so a submission missing both
// required entries always names the same one in its error rather than
// whichever the map's iteration order surfaced that run.
var (
	allowedEntries = map[string]bool{
		ValidatorLogFileName: true,
		SentryLogFileName:    true,
		MetadataFileName:     true,
	}
	requiredEntries = []string{ValidatorLogFileName, MetadataFileName}
)

// logEntries is the subset of allowedEntries ScanLogs visits.
var logEntries = map[string]bool{
	ValidatorLogFileName: true,
	SentryLogFileName:    true,
}

// Options bounds how much of each archive entry ValidateArchive will
// read, independent of what the archive itself claims. Zero values fall
// back to conservative defaults.
type Options struct {
	MaxLogSize      int64
	MaxMetadataSize int64
}

func (o Options) withDefaults() Options {
	if o.MaxLogSize <= 0 {
		o.MaxLogSize = defaultMaxLogSize
	}
	if o.MaxMetadataSize <= 0 {
		o.MaxMetadataSize = defaultMaxMetadataSize
	}
	return o
}

// Result holds what ValidateArchive learned. Metadata is the raw,
// still-unvalidated content of metadata.json — pass it to
// ValidateMetadata separately; filename/structure checks and metadata
// *content* checks are different concerns with different failure modes.
//
// Neither log entry is carried here. Each is validated in place — magic
// bytes checked, the rest drained and counted without ever being
// buffered — and then dropped, so memory for either stays O(1) regardless
// of its size; callers that need the content (see the scoring package)
// stream it back out with OpenLog.
type Result struct {
	Metadata []byte

	// SentryLogPresent records whether the optional sentry.log.gz entry
	// was in the archive. It is carried out of here because the only
	// other way to answer it is a second walk of the tar, and the
	// question outlives this function: scoring reports "no sentry log
	// submitted" differently from "a sentry log we could not parse".
	SentryLogPresent bool
}

// ValidateArchive streams through r (expected to be a gzip-compressed
// tar) and enforces prd.md's "Security Considerations":
//
//   - Only the three known entries are accepted; anything else fails the
//     whole archive closed (fail-closed on the first violation).
//     sentry.log.gz is optional — its absence is not a failure — but any
//     other unrecognised name is.
//   - Path traversal is blocked by exact-name allowlisting rather than
//     pattern blocklisting: an entry named "../etc/passwd" or
//     "sub/validator.log.gz" simply never matches an allowed name.
//   - Only regular files are accepted — symlinks, hardlinks,
//     directories, and device entries are all rejected.
//   - No duplicate entries.
//   - Each entry is read through a bounded reader, so decompression cost
//     is capped by Options regardless of what the archive's headers or
//     compression ratio claim (defends against zip/tar bombs without
//     trusting declared sizes). For metadata.json that bound is on
//     memory too — it's small (64 KiB) and genuinely needed by the
//     caller, so it's read into memory whole. For validator.log.gz and
//     sentry.log.gz — potentially hundreds of MB — memory is O(1)
//     regardless of MaxLogSize: each is drained and counted without ever
//     being buffered, so the Options bound there caps decompression
//     time, not resident memory.
//
// ValidateArchive never writes the archive anywhere; storing the
// original raw bytes after successful validation is the caller's
// responsibility (see the storage package).
func ValidateArchive(ctx context.Context, r io.Reader, opts Options) (Result, error) {
	opts = opts.withDefaults()

	gz, err := gzip.NewReader(r)
	if err != nil {
		return Result{}, fmt.Errorf("not a valid gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	seen := make(map[string]bool, len(allowedEntries))
	var metadata []byte
	var sentryPresent bool

	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Result{}, fmt.Errorf("corrupt tar stream: %w", err)
		}

		if !allowedEntries[hdr.Name] {
			return Result{}, fmt.Errorf("unexpected archive entry %q: only %s, %s, and %s are accepted", hdr.Name, ValidatorLogFileName, SentryLogFileName, MetadataFileName)
		}
		if seen[hdr.Name] {
			return Result{}, fmt.Errorf("duplicate archive entry %q", hdr.Name)
		}
		seen[hdr.Name] = true

		if hdr.Typeflag != tar.TypeReg {
			return Result{}, fmt.Errorf("archive entry %q is not a regular file (tar type %q is not allowed)", hdr.Name, string(hdr.Typeflag))
		}

		switch hdr.Name {
		case ValidatorLogFileName, SentryLogFileName:
			// Both logs get identical treatment: they can be hundreds of
			// MB, so unlike metadata.json below neither is ever
			// materialised — readBounded drains each through a bounded
			// reader, counting bytes as it goes, and hands back only the
			// first two (the gzip magic) that ever needed inspecting.
			n, magic, err := readBounded(tr, opts.MaxLogSize)
			if err != nil {
				return Result{}, fmt.Errorf("reading archive entry %q: %w", hdr.Name, err)
			}
			if n > opts.MaxLogSize {
				return Result{}, fmt.Errorf("archive entry %q exceeds the %d byte limit", hdr.Name, opts.MaxLogSize)
			}
			if n < 2 || magic[0] != 0x1f || magic[1] != 0x8b {
				return Result{}, fmt.Errorf("%s does not look like a gzip file (bad magic bytes)", hdr.Name)
			}
			if hdr.Name == SentryLogFileName {
				sentryPresent = true
			}

		case MetadataFileName:
			// metadata.json is bounded to 64 KiB by default and its
			// content is genuinely needed by the caller, so — unlike
			// the log entries above — it's fine, and simpler, to hold the
			// whole thing in memory.
			//
			// Read up to limit+1 so a file that's exactly at the limit
			// can be told apart from one that overflows it, without ever
			// buffering more than limit+1 bytes no matter what hdr.Size
			// or the compression ratio claims.
			limit := opts.MaxMetadataSize
			data, err := io.ReadAll(io.LimitReader(tr, limit+1))
			if err != nil {
				return Result{}, fmt.Errorf("reading archive entry %q: %w", hdr.Name, err)
			}
			if int64(len(data)) > limit {
				return Result{}, fmt.Errorf("archive entry %q exceeds the %d byte limit", hdr.Name, limit)
			}
			metadata = data
		}
	}

	for _, name := range requiredEntries {
		if !seen[name] {
			return Result{}, fmt.Errorf("archive is missing required entry %q", name)
		}
	}

	return Result{Metadata: metadata, SentryLogPresent: sentryPresent}, nil
}

// OpenLog walks r — which must be a rewound reader over an archive
// ValidateArchive has already accepted — and returns a reader over the
// gnoland.log.gz entry, bounded to opts.MaxLogSize. The bytes are never
// buffered: callers stream them, so an archive at the size limit costs
// decompression time rather than that much resident memory.
//
// The returned ReadCloser owns the underlying gzip reader, so callers must
// Close it. The stream is only valid until then, and reading it consumes r.
//
// OpenLog deliberately does not re-run ValidateArchive's structural checks
// (allowed names, duplicates, file types, required entries) — those are
// that function's job and are not duplicated here. The MaxLogSize bound is
// kept as defence in depth against a caller that skipped validation, not
// because a validated archive could exceed it.
func OpenLog(ctx context.Context, r io.Reader, opts Options) (io.ReadCloser, error) {
	opts = opts.withDefaults()

	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a valid gzip stream: %w", err)
	}

	tr := tar.NewReader(gz)
	for {
		if err := ctx.Err(); err != nil {
			gz.Close()
			return nil, err
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			gz.Close()
			return nil, fmt.Errorf("archive is missing required entry %q", ValidatorLogFileName)
		}
		if err != nil {
			gz.Close()
			return nil, fmt.Errorf("corrupt tar stream: %w", err)
		}
		if hdr.Name != ValidatorLogFileName {
			continue
		}

		// tr's per-entry reader stays valid only until the next Next call,
		// which is why this returns from inside the loop rather than
		// breaking out to shared cleanup.
		return logStream{Reader: io.LimitReader(tr, opts.MaxLogSize), closer: gz}, nil
	}
}

// logStream ties the bounded per-entry reader to the gzip reader backing
// it, so a single Close releases both.
type logStream struct {
	io.Reader
	closer io.Closer
}

func (s logStream) Close() error { return s.closer.Close() }

// ScanLogs walks r — which must be a rewound reader over an archive
// ValidateArchive has already accepted — and calls fn once per log
// entry, with a reader bounded to opts.MaxLogSize.
//
// The callback shape is what keeps this to a single walk. A tar entry's
// reader is only valid until the next Next call, so a function handing
// streams back to its caller can only ever hand back one, and reading
// two entries would cost two walks — two decompressions of the outer
// gzip over an archive that may run to gigabytes. fn need not consume
// its entry: Next skips whatever is left, which is what lets the
// antivirus pass decline an entry once its budget is spent.
//
// fn's error is returned unwrapped, so a caller's sentinel survives
// errors.Is.
//
// ScanLogs deliberately does not re-run ValidateArchive's structural
// checks (allowed names, duplicates, file types, required entries) —
// those are that function's job and are not duplicated here. The
// MaxLogSize bound is kept as defence in depth against a caller that
// skipped validation, not because a validated archive could exceed it.
func ScanLogs(ctx context.Context, r io.Reader, opts Options, fn func(name string, log io.Reader) error) error {
	opts = opts.withDefaults()

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("not a valid gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("corrupt tar stream: %w", err)
		}
		if !logEntries[hdr.Name] {
			continue
		}

		if err := fn(hdr.Name, io.LimitReader(tr, opts.MaxLogSize)); err != nil {
			return err
		}
	}
}

// readBounded drains r — already positioned at the start of a tar entry —
// without ever buffering it, and returns the total byte count read plus
// the first two bytes seen (the log entry's gzip magic; zero-valued if
// fewer than two bytes were available).
//
// It reads up to limit+1 bytes total, the same "one past the limit" trick
// ValidateArchive's metadata.json path uses via
// io.ReadAll(io.LimitReader(...)): it lets the caller tell an entry sitting
// exactly at limit apart from one that overflows it, without ever holding
// more than two bytes in memory at once no matter what hdr.Size or the
// compression ratio claims.
func readBounded(r io.Reader, limit int64) (n int64, magic [2]byte, err error) {
	lr := io.LimitReader(r, limit+1)

	mn, err := io.ReadFull(lr, magic[:])
	n = int64(mn)
	if err != nil {
		// Fewer than two bytes total isn't a read failure — it's an
		// entry too short to have a valid gzip magic, which the caller
		// checks for itself from n and magic.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return n, magic, nil
		}
		return n, magic, err
	}

	rest, err := io.Copy(io.Discard, lr)
	return n + rest, magic, err
}
