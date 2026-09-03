package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/scoring"
)

var testWindowStart = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
var testWindowEnd = time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)

func gzipBytes(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(content)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// writeArchive builds the same shape submission.ValidateArchive accepts:
// a gzip-compressed tar holding validator.log.gz and metadata.json at the
// root.
func writeArchive(t *testing.T, path, logContent string) {
	t.Helper()

	meta, err := json.Marshal(map[string]any{
		"validator_address": "g1testvalidator00000000000000000000000",
		"moniker":           "testnode",
		"chain_id":          "pearl-1",
		"gnoland_version":   "chain/pearl",
		"genesis_sha256":    "c45fe60c",
		"operating_system":  "Debian 12",
		"architecture":      "amd64",
		"sentry_enabled":    false,
		"backup_node":       true,
		"hosting_provider":  "Scaleway",
		"deployment_method": "systemd",
		"recent_operations": "None",
	})
	if err != nil {
		t.Fatalf("marshalling metadata: %v", err)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, entry := range []struct {
		name string
		body []byte
	}{
		{"validator.log.gz", gzipBytes(t, logContent)},
		{"metadata.json", meta},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name:     entry.name,
			Mode:     0o644,
			Size:     int64(len(entry.body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header for %s: %v", entry.name, err)
		}
		if _, err := tw.Write(entry.body); err != nil {
			t.Fatalf("tar body for %s: %v", entry.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// fixture lays out one drill on disk: a submission whose log is in
// journalctl's default format — readable, covering the window, and
// exactly what the old timestamp detection scored at zero.
type fixture struct {
	archives    string
	submissions string
	exercise    string
	scores      string
	id          string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	f := fixture{
		archives:    filepath.Join(dir, "archives"),
		submissions: filepath.Join(dir, "submissions.jsonl"),
		exercise:    filepath.Join(dir, "exercise.json"),
		scores:      filepath.Join(dir, "scores.json"),
		id:          "submission-1",
	}
	if err := os.MkdirAll(f.archives, 0o755); err != nil {
		t.Fatalf("creating the archive dir: %v", err)
	}

	writeArchive(t, filepath.Join(f.archives, "testnode-20260901-1200UTC.tar.gz"),
		"Sep  1 12:00:00 host gnoland[1]: 2026-09-01T12:00:00.322Z#011#033[34mINFO #033[0m#011starting\n"+
			"Sep  1 13:59:59 host gnoland[1]: 2026-09-01T13:59:59.998Z#011#033[34mINFO #033[0m#011stopping\n")

	entry := portal.Entry{
		ID:              f.id,
		Moniker:         "testnode",
		OperatorAddress: "g1testvalidator00000000000000000000000",
		Filename:        "testnode-20260901-1200UTC.tar.gz",
		SubmittedAt:     time.Date(2026, 9, 2, 17, 0, 0, 0, time.UTC),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshalling the entry: %v", err)
	}
	if err := os.WriteFile(f.submissions, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("writing the submissions log: %v", err)
	}

	cfg, err := json.Marshal(exercise.Config{
		AnnouncedAt:              time.Date(2026, 9, 2, 16, 0, 0, 0, time.UTC),
		DeadlineAt:               time.Date(2026, 9, 3, 16, 0, 0, 0, time.UTC),
		InvestigationWindowStart: testWindowStart,
		InvestigationWindowEnd:   testWindowEnd,
		ExpectedGenesisSHA256:    "c45fe60c",
		SupportedGnolandVersions: []string{"chain/pearl"},
	})
	if err != nil {
		t.Fatalf("marshalling the exercise config: %v", err)
	}
	if err := os.WriteFile(f.exercise, cfg, 0o644); err != nil {
		t.Fatalf("writing the exercise config: %v", err)
	}

	return f
}

// seedStaleScore writes the record the portal produced under the old
// timestamp detection: scored, but with nothing found in the log, plus a
// manually entered incident-response score.
func (f fixture) seedStaleScore(t *testing.T, manual *int) {
	t.Helper()
	stale := map[string]scoring.Result{
		f.id: {
			SubmissionID:                 f.id,
			Scored:                       true,
			GenesisMatch:                 true,
			VersionSupported:             true,
			LogWindow:                    scoring.LogWindowCheck{},
			UploadTimeScore:              25,
			MetadataScore:                25,
			LogQualityScore:              13,
			IncidentResponseQualityScore: manual,
		},
	}
	data, err := json.Marshal(stale)
	if err != nil {
		t.Fatalf("marshalling the stale scores: %v", err)
	}
	if err := os.WriteFile(f.scores, data, 0o644); err != nil {
		t.Fatalf("writing the stale scores: %v", err)
	}
}

func (f fixture) result(t *testing.T) scoring.Result {
	t.Helper()
	r, ok, err := scoring.NewStore(f.scores).Get(f.id)
	if err != nil {
		t.Fatalf("reading back the score: %v", err)
	}
	if !ok {
		t.Fatalf("no score recorded for %s", f.id)
	}
	return r
}

func TestRun_RecomputesFromStoredArchive(t *testing.T) {
	f := newFixture(t)
	manual := 20
	f.seedStaleScore(t, &manual)

	if err := run(f.archives, f.submissions, f.exercise, f.scores, defaultMaxLogSize, true); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := f.result(t)
	if !got.LogWindow.Detected {
		t.Errorf("LogWindow.Detected = false, want true: the log is in journalctl's default format")
	}
	if !got.LogWindow.Covered {
		t.Errorf("LogWindow = %+v, want Covered", got.LogWindow)
	}
	// 13 structural + 8 for a covered validator log, with no sentry log.
	if got.LogQualityScore != 21 {
		t.Errorf("LogQualityScore = %d, want 21", got.LogQualityScore)
	}
	if got.UploadTimeScore != 25 {
		t.Errorf("UploadTimeScore = %d, want 25: scored from the recorded submission time (an hour into a 24h window), not from the time of the rescore, which is past the deadline and would score 0", got.UploadTimeScore)
	}
}

func TestRun_PreservesManuallyEnteredScore(t *testing.T) {
	// The rescore recomputes what the code can observe. An admin's
	// incident-response mark is not that, and silently dropping it would
	// turn a finished submission back into a pending one.
	f := newFixture(t)
	manual := 20
	f.seedStaleScore(t, &manual)

	if err := run(f.archives, f.submissions, f.exercise, f.scores, defaultMaxLogSize, true); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := f.result(t)
	if got.IncidentResponseQualityScore == nil {
		t.Fatal("IncidentResponseQualityScore = nil, want the manually entered 20 to survive")
	}
	if *got.IncidentResponseQualityScore != 20 {
		t.Errorf("IncidentResponseQualityScore = %d, want 20", *got.IncidentResponseQualityScore)
	}
	if got.Pending() {
		t.Error("Pending() = true, want false")
	}
}

func TestRun_WithoutApplyWritesNothing(t *testing.T) {
	f := newFixture(t)
	f.seedStaleScore(t, nil)
	before, err := os.ReadFile(f.scores)
	if err != nil {
		t.Fatalf("reading the seeded scores: %v", err)
	}

	if err := run(f.archives, f.submissions, f.exercise, f.scores, defaultMaxLogSize, false); err != nil {
		t.Fatalf("run: %v", err)
	}

	after, err := os.ReadFile(f.scores)
	if err != nil {
		t.Fatalf("reading the scores back: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the scores file changed without -apply:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestRun_RefusesAnUnconfiguredExercise(t *testing.T) {
	// Scoring against a zero Config gives every submission zero for
	// timing and a failed check for everything else. Overwriting real
	// results with that is worse than doing nothing.
	f := newFixture(t)
	f.seedStaleScore(t, nil)
	if err := os.WriteFile(f.exercise, []byte("{}"), 0o644); err != nil {
		t.Fatalf("blanking the exercise config: %v", err)
	}

	if err := run(f.archives, f.submissions, f.exercise, f.scores, defaultMaxLogSize, true); err == nil {
		t.Fatal("run() = nil, want an error for an unconfigured exercise")
	}
}

func TestRun_SkipsAMissingArchiveWithoutTouchingTheRest(t *testing.T) {
	// An archive that cannot be read leaves the portal's own record in
	// place rather than replacing it with a zero.
	f := newFixture(t)
	manual := 20
	f.seedStaleScore(t, &manual)
	if err := os.Remove(filepath.Join(f.archives, "testnode-20260901-1200UTC.tar.gz")); err != nil {
		t.Fatalf("removing the archive: %v", err)
	}

	if err := run(f.archives, f.submissions, f.exercise, f.scores, defaultMaxLogSize, true); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := f.result(t)
	if got.LogQualityScore != 13 {
		t.Errorf("LogQualityScore = %d, want the stale 13 left untouched", got.LogQualityScore)
	}
}
