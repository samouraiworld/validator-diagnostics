package submission

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"testing"
)

type tarEntry struct {
	name     string
	typeflag byte
	content  []byte
	linkname string
}

func buildTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: typeflag,
			Size:     int64(len(e.content)),
			Mode:     0o644,
			Linkname: e.linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", e.name, err)
		}
		if len(e.content) > 0 {
			if _, err := tw.Write(e.content); err != nil {
				t.Fatalf("Write(%q): %v", e.name, err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	return buf.Bytes()
}

// validLogContent starts with the gzip magic bytes, as a real
// gnoland.log.gz would (it's itself gzip-compressed log content, nested
// inside the outer tar.gz).
var validLogContent = append([]byte{0x1f, 0x8b}, []byte("fake gzip log payload")...)

var validMetadataContent = []byte(`{
  "validator_address": "g1abc",
  "moniker": "samourai",
  "chain_id": "topaz-1",
  "gnoland_version": "v1.0.0",
  "genesis_sha256": "deadbeef",
  "operating_system": "Debian 12",
  "architecture": "amd64",
  "sentry_enabled": true,
  "backup_node": true,
  "hosting_provider": "Scaleway",
  "deployment_method": "docker",
  "recent_operations": "None"
}`)

func TestValidateArchive_Valid(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	result, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{})
	if err != nil {
		t.Fatalf("ValidateArchive: unexpected error: %v", err)
	}
	if string(result.Metadata) != string(validMetadataContent) {
		t.Errorf("Metadata mismatch")
	}
	if len(result.LogGz) == 0 {
		t.Error("result.LogGz is empty, want the gnoland.log.gz bytes")
	}
	if result.LogGz[0] != 0x1f || result.LogGz[1] != 0x8b {
		t.Errorf("result.LogGz does not start with gzip magic bytes: %x", result.LogGz[:2])
	}
}

func TestValidateArchive_RejectsUnexpectedEntry(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
		{name: "extra.txt", content: []byte("surprise")},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected an error for an unexpected archive entry, got nil")
	}
}

func TestValidateArchive_RejectsPathTraversal(t *testing.T) {
	for _, name := range []string{
		"../" + LogFileName,
		"../../etc/passwd",
		"sub/" + LogFileName,
		"/etc/" + LogFileName,
	} {
		t.Run(name, func(t *testing.T) {
			data := buildTarGz(t, []tarEntry{
				{name: name, content: validLogContent},
				{name: MetadataFileName, content: validMetadataContent},
			})

			if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
				t.Fatalf("expected entry %q to be rejected, got nil error", name)
			}
		})
	}
}

func TestValidateArchive_RejectsSymlink(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected a symlink entry to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsHardlink(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, typeflag: tar.TypeLink, linkname: MetadataFileName},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected a hardlink entry to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsDirectory(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, typeflag: tar.TypeDir},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected a directory entry to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsDuplicateEntry(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: MetadataFileName, content: validMetadataContent},
		{name: MetadataFileName, content: validMetadataContent},
		{name: LogFileName, content: validLogContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected a duplicate entry to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsMissingEntry(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected an archive missing gnoland.log.gz to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsOversizedEntry(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	_, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{MaxMetadataSize: 4})
	if err == nil {
		t.Fatal("expected an oversized metadata.json to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsBadLogMagicBytes(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, content: []byte("not actually gzip")},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected gnoland.log.gz without gzip magic bytes to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsNonGzipInput(t *testing.T) {
	_, err := ValidateArchive(context.Background(), bytes.NewReader([]byte("this is not gzip at all")), Options{})
	if err == nil {
		t.Fatal("expected non-gzip input to be rejected, got nil")
	}
}
