package submission

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
)

const (
	LogFileName      = "gnoland.log.gz"
	MetadataFileName = "metadata.json"

	defaultMaxLogSize      = 2 << 30 // 2 GiB
	defaultMaxMetadataSize = 64 << 10
)

var allowedEntries = map[string]bool{
	LogFileName:      true,
	MetadataFileName: true,
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
// LogGz is the raw, still-gzip-compressed bytes of gnoland.log.gz,
// already bounded by Options.MaxLogSize — callers that need to look
// inside the log (see the scoring package) should use this instead of
// re-reading the raw upload, to avoid two independent parsers
// interpreting the same untrusted archive differently.
type Result struct {
	Metadata []byte
	LogGz    []byte
}

// ValidateArchive streams through r (expected to be a gzip-compressed
// tar) and enforces prd.md's "Security Considerations":
//
//   - Only the two expected entries are accepted; anything else fails
//     the whole archive closed (fail-closed on the first violation).
//   - Path traversal is blocked by exact-name allowlisting rather than
//     pattern blocklisting: an entry named "../etc/passwd" or
//     "sub/gnoland.log.gz" simply never matches an allowed name.
//   - Only regular files are accepted — symlinks, hardlinks,
//     directories, and device entries are all rejected.
//   - No duplicate entries.
//   - Each entry is read through a bounded reader, so decompression
//     cost/memory is capped by Options regardless of what the archive's
//     headers or compression ratio claim (defends against zip/tar
//     bombs without trusting declared sizes).
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
	var logGz []byte

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
			return Result{}, fmt.Errorf("unexpected archive entry %q: only %s and %s are accepted", hdr.Name, LogFileName, MetadataFileName)
		}
		if seen[hdr.Name] {
			return Result{}, fmt.Errorf("duplicate archive entry %q", hdr.Name)
		}
		seen[hdr.Name] = true

		if hdr.Typeflag != tar.TypeReg {
			return Result{}, fmt.Errorf("archive entry %q is not a regular file (tar type %q is not allowed)", hdr.Name, string(hdr.Typeflag))
		}

		limit := opts.MaxMetadataSize
		if hdr.Name == LogFileName {
			limit = opts.MaxLogSize
		}

		// Read up to limit+1 so a file that's exactly at the limit can
		// be told apart from one that overflows it, without ever
		// buffering more than limit+1 bytes no matter what hdr.Size or
		// the compression ratio claims.
		data, err := io.ReadAll(io.LimitReader(tr, limit+1))
		if err != nil {
			return Result{}, fmt.Errorf("reading archive entry %q: %w", hdr.Name, err)
		}
		if int64(len(data)) > limit {
			return Result{}, fmt.Errorf("archive entry %q exceeds the %d byte limit", hdr.Name, limit)
		}

		switch hdr.Name {
		case LogFileName:
			if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
				return Result{}, fmt.Errorf("%s does not look like a gzip file (bad magic bytes)", LogFileName)
			}
			logGz = data
		case MetadataFileName:
			metadata = data
		}
	}

	for name := range allowedEntries {
		if !seen[name] {
			return Result{}, fmt.Errorf("archive is missing required entry %q", name)
		}
	}

	return Result{Metadata: metadata, LogGz: logGz}, nil
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
			return nil, fmt.Errorf("archive is missing required entry %q", LogFileName)
		}
		if err != nil {
			gz.Close()
			return nil, fmt.Errorf("corrupt tar stream: %w", err)
		}
		if hdr.Name != LogFileName {
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
