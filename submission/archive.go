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
//
// The gnoland.log.gz entry is deliberately not carried here. It is
// validated in place — magic bytes checked, the rest drained and counted
// without ever being buffered — and then dropped, so memory for that
// entry stays O(1) regardless of its size; callers that need its content
// (see the scoring package) stream it back out with OpenLog.
type Result struct {
	Metadata []byte
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
//   - Each entry is read through a bounded reader, so decompression cost
//     is capped by Options regardless of what the archive's headers or
//     compression ratio claim (defends against zip/tar bombs without
//     trusting declared sizes). For metadata.json that bound is on
//     memory too — it's small (64 KiB) and genuinely needed by the
//     caller, so it's read into memory whole. For gnoland.log.gz —
//     potentially hundreds of MB — memory is O(1) regardless of
//     MaxLogSize: it's drained and counted without ever being buffered,
//     so the Options bound there caps decompression time, not resident
//     memory.
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

		switch hdr.Name {
		case LogFileName:
			// gnoland.log.gz can be hundreds of MB, so unlike
			// metadata.json below it is never materialised: readBounded
			// drains it through a bounded reader, counting bytes as it
			// goes, and hands back only the first two (the gzip magic)
			// that ever needed inspecting.
			n, magic, err := readBounded(tr, opts.MaxLogSize)
			if err != nil {
				return Result{}, fmt.Errorf("reading archive entry %q: %w", hdr.Name, err)
			}
			if n > opts.MaxLogSize {
				return Result{}, fmt.Errorf("archive entry %q exceeds the %d byte limit", hdr.Name, opts.MaxLogSize)
			}
			if n < 2 || magic[0] != 0x1f || magic[1] != 0x8b {
				return Result{}, fmt.Errorf("%s does not look like a gzip file (bad magic bytes)", LogFileName)
			}

		case MetadataFileName:
			// metadata.json is bounded to 64 KiB by default and its
			// content is genuinely needed by the caller, so — unlike
			// gnoland.log.gz above — it's fine, and simpler, to hold the
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

	for name := range allowedEntries {
		if !seen[name] {
			return Result{}, fmt.Errorf("archive is missing required entry %q", name)
		}
	}

	return Result{Metadata: metadata}, nil
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

// readBounded drains r — already positioned at the start of a tar entry —
// without ever buffering it, and returns the total byte count read plus
// the first two bytes seen (gnoland.log.gz's gzip magic; zero-valued if
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
