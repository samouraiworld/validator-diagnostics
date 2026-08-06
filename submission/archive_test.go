package submission

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
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
		{name: ValidatorLogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	result, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{})
	if err != nil {
		t.Fatalf("ValidateArchive: unexpected error: %v", err)
	}
	if string(result.Metadata) != string(validMetadataContent) {
		t.Errorf("Metadata mismatch")
	}
}

func TestValidateArchive_RejectsUnexpectedEntry(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
		{name: "extra.txt", content: []byte("surprise")},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected an error for an unexpected archive entry, got nil")
	}
}

func TestValidateArchive_RejectsPathTraversal(t *testing.T) {
	for _, name := range []string{
		"../" + ValidatorLogFileName,
		"../../etc/passwd",
		"sub/" + ValidatorLogFileName,
		"/etc/" + ValidatorLogFileName,
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
		{name: ValidatorLogFileName, typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected a symlink entry to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsHardlink(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, typeflag: tar.TypeLink, linkname: MetadataFileName},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected a hardlink entry to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsDirectory(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, typeflag: tar.TypeDir},
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
		{name: ValidatorLogFileName, content: validLogContent},
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
		{name: ValidatorLogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	_, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{MaxMetadataSize: 4})
	if err == nil {
		t.Fatal("expected an oversized metadata.json to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsOversizedLogEntry(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	_, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{MaxLogSize: 4})
	if err == nil {
		t.Fatal("expected an oversized gnoland.log.gz to be rejected, got nil")
	}
}

func TestValidateArchive_AcceptsLogEntryExactlyAtMaxLogSize(t *testing.T) {
	// Pins the exact-boundary semantics of the log path's bounded read: an
	// entry of exactly MaxLogSize bytes is accepted, not rejected as
	// oversized.
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	_, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{MaxLogSize: int64(len(validLogContent))})
	if err != nil {
		t.Fatalf("expected a log entry exactly at MaxLogSize to be accepted, got: %v", err)
	}
}

func TestValidateArchive_RejectsBadLogMagicBytes(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: []byte("not actually gzip")},
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

func TestValidateArchive_RejectsOldGnolandLogName(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: "gnoland.log.gz", content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected gnoland.log.gz to be rejected after the rename, got nil")
	}
}

func TestValidateArchive_AcceptsOptionalSentryLog(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: validLogContent},
		{name: SentryLogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	result, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{})
	if err != nil {
		t.Fatalf("ValidateArchive: unexpected error: %v", err)
	}
	if !result.SentryLogPresent {
		t.Error("SentryLogPresent = false, want true")
	}
}

func TestValidateArchive_SentryLogIsOptional(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	result, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{})
	if err != nil {
		t.Fatalf("ValidateArchive: unexpected error: %v", err)
	}
	if result.SentryLogPresent {
		t.Error("SentryLogPresent = true, want false")
	}
}

func TestValidateArchive_RejectsMissingValidatorLog(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: SentryLogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected an archive without validator.log.gz to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsSentryLogWithBadMagic(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: validLogContent},
		{name: SentryLogFileName, content: []byte("not gzip at all")},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected a sentry log with bad gzip magic to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsOversizedSentryLog(t *testing.T) {
	content := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte("x"), 64)...)
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: validLogContent},
		{name: SentryLogFileName, content: content},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{MaxLogSize: 8}); err == nil {
		t.Fatal("expected an oversized sentry log to be rejected, got nil")
	}
}

func TestValidateArchive_RejectsDuplicateSentryLog(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: validLogContent},
		{name: SentryLogFileName, content: validLogContent},
		{name: SentryLogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	if _, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{}); err == nil {
		t.Fatal("expected a duplicate sentry log entry to be rejected, got nil")
	}
}

func TestScanLogs_VisitsBothLogs(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: []byte("validator payload")},
		{name: SentryLogFileName, content: []byte("sentry payload")},
		{name: MetadataFileName, content: validMetadataContent},
	})

	seen := map[string]string{}
	err := ScanLogs(context.Background(), bytes.NewReader(data), Options{}, func(name string, log io.Reader) error {
		body, err := io.ReadAll(log)
		if err != nil {
			return err
		}
		seen[name] = string(body)
		return nil
	})
	if err != nil {
		t.Fatalf("ScanLogs: unexpected error: %v", err)
	}

	if got := seen[ValidatorLogFileName]; got != "validator payload" {
		t.Errorf("validator log = %q, want %q", got, "validator payload")
	}
	if got := seen[SentryLogFileName]; got != "sentry payload" {
		t.Errorf("sentry log = %q, want %q", got, "sentry payload")
	}
	if len(seen) != 2 {
		t.Errorf("visited %d entries, want 2 (metadata.json must not be visited)", len(seen))
	}
}

func TestScanLogs_VisitsOnlyTheValidatorLogWhenNoSentry(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: []byte("validator payload")},
		{name: MetadataFileName, content: validMetadataContent},
	})

	var names []string
	err := ScanLogs(context.Background(), bytes.NewReader(data), Options{}, func(name string, log io.Reader) error {
		names = append(names, name)
		return nil
	})
	if err != nil {
		t.Fatalf("ScanLogs: unexpected error: %v", err)
	}
	if len(names) != 1 || names[0] != ValidatorLogFileName {
		t.Errorf("visited %v, want [%s]", names, ValidatorLogFileName)
	}
}

func TestScanLogs_CallbackErrorAbortsTheWalkUnwrapped(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: []byte("validator payload")},
		{name: SentryLogFileName, content: []byte("sentry payload")},
		{name: MetadataFileName, content: validMetadataContent},
	})

	sentinel := errors.New("stop here")
	var calls int
	err := ScanLogs(context.Background(), bytes.NewReader(data), Options{}, func(name string, log io.Reader) error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("ScanLogs error = %v, want it to wrap the callback's sentinel", err)
	}
	if calls != 1 {
		t.Errorf("callback called %d times, want 1 (the walk must stop on error)", calls)
	}
}

func TestScanLogs_UnreadEntryDoesNotBreakTheWalk(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: bytes.Repeat([]byte("x"), 4096)},
		{name: SentryLogFileName, content: []byte("sentry payload")},
		{name: MetadataFileName, content: validMetadataContent},
	})

	var names []string
	err := ScanLogs(context.Background(), bytes.NewReader(data), Options{}, func(name string, log io.Reader) error {
		// Deliberately does not consume the entry: scanArchive declines
		// an entry once its AV budget is spent.
		names = append(names, name)
		return nil
	})
	if err != nil {
		t.Fatalf("ScanLogs: unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("visited %v, want both logs even though neither was read", names)
	}
}

func TestScanLogs_BoundsEachEntry(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: ValidatorLogFileName, content: bytes.Repeat([]byte("x"), 64)},
		{name: MetadataFileName, content: validMetadataContent},
	})

	var n int
	err := ScanLogs(context.Background(), bytes.NewReader(data), Options{MaxLogSize: 8}, func(name string, log io.Reader) error {
		body, err := io.ReadAll(log)
		n = len(body)
		return err
	})
	if err != nil {
		t.Fatalf("ScanLogs: unexpected error: %v", err)
	}
	if n != 8 {
		t.Errorf("read %d bytes, want 8 (MaxLogSize must bound the entry reader)", n)
	}
}
