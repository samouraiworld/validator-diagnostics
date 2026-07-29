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
		case MetadataFileName:
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
