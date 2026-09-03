// Command rescore recomputes the automatic half of every recorded
// submission's score from the archives kept on disk, and rewrites the
// scores file in place.
//
// The portal scores a submission once, during the upload request, and
// keeps nothing of the log afterwards — the bytes are streamed straight
// out of the request and never retained (see portal.autoChecks). So when
// a scoring check turns out to be wrong, as the timestamp detection was
// for the 2026-09-02 drill, there is no way to correct the recorded
// results from inside the portal. The stored archives are the only
// remaining source, and this reads them back.
//
// The manually entered criterion is carried across untouched: this
// recomputes what the code can observe, and an admin's incident-response
// score is not that.
//
// Nothing is written without -apply.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/submission"
)

// defaultMaxLogSize matches cmd/portal's own default. Re-scoring under a
// tighter bound than the upload was accepted with would report a log as
// unreadable that the portal had already read.
const defaultMaxLogSize = 4294967296 // 4 GiB

func main() {
	log.SetFlags(0)

	archivesDir := flag.String("archives", "", "directory holding the stored submission archives (required)")
	submissionsPath := flag.String("submissions", "", "path to the submissions log written by the portal (required)")
	exercisePath := flag.String("exercise", "", "path to the exercise configuration file (required)")
	scoresPath := flag.String("scores", "", "path to the scores file to recompute (required)")
	maxLogSize := flag.Int64("max-log-size", defaultMaxLogSize, "maximum accepted size in bytes of each log entry inside the archive; must be at least what the portal accepted the upload with")
	apply := flag.Bool("apply", false, "write the recomputed scores; without it the run only reports what would change")
	flag.Parse()

	missing := ""
	switch {
	case *archivesDir == "":
		missing = "-archives"
	case *submissionsPath == "":
		missing = "-submissions"
	case *exercisePath == "":
		missing = "-exercise"
	case *scoresPath == "":
		missing = "-scores"
	}
	if missing != "" {
		log.Fatalf("rescore: %s is required", missing)
	}

	if err := run(*archivesDir, *submissionsPath, *exercisePath, *scoresPath, *maxLogSize, *apply); err != nil {
		log.Fatalf("rescore: %v", err)
	}
}

func run(archivesDir, submissionsPath, exercisePath, scoresPath string, maxLogSize int64, apply bool) error {
	cfg, err := exercise.NewFileStore(exercisePath).Get()
	if err != nil {
		return fmt.Errorf("reading the exercise config: %w", err)
	}
	// Every automatic score is computed against the window, the expected
	// genesis hash and the supported versions. Without them TieredTimeScore
	// returns 0 and every check fails, so a run here would quietly replace
	// real results with zeros.
	if !cfg.Configured() {
		return fmt.Errorf("the exercise in %s is not configured; there is nothing to score against", exercisePath)
	}

	entries, err := portal.NewFileLog(submissionsPath).Entries()
	if err != nil {
		return fmt.Errorf("reading the submissions log: %w", err)
	}

	scores := scoring.NewStore(scoresPath)
	previous, err := scores.ByID()
	if err != nil {
		return fmt.Errorf("reading the current scores: %w", err)
	}

	opts := submission.Options{MaxLogSize: maxLogSize}
	var changed, failed int

	for _, e := range entries {
		before, hadBefore := previous[e.ID]

		after, err := rescoreOne(filepath.Join(archivesDir, e.Filename), opts, e, cfg)
		if err != nil {
			// One unreadable archive must not cost the other 45 their
			// correction, and leaving the old record in place is the
			// conservative outcome: it is what the portal already
			// published.
			log.Printf("%-26s SKIPPED  %v", e.Moniker, err)
			failed++
			continue
		}
		// The admin's manual entry is not something this can observe or
		// recompute, so it survives the rewrite verbatim.
		if hadBefore {
			after.IncidentResponseQualityScore = before.IncidentResponseQualityScore
		}

		beforeTotal := 0
		if hadBefore && before.Scored {
			beforeTotal = before.TotalScore()
		}
		afterTotal := after.TotalScore()
		if beforeTotal != afterTotal {
			changed++
		}

		log.Printf("%-26s %3d -> %3d  %+4d  %s", e.Moniker, beforeTotal, afterTotal, afterTotal-beforeTotal, describe(after))

		if apply {
			if err := scores.Set(after); err != nil {
				return fmt.Errorf("writing the score for %s: %w", e.Moniker, err)
			}
		}
	}

	log.Printf("")
	log.Printf("%d submission(s), %d with a changed total, %d skipped", len(entries), changed, failed)
	if !apply {
		log.Printf("nothing was written; re-run with -apply to save these scores")
	}
	return nil
}

// rescoreOne reruns the automatic checks for one submission against its
// stored archive, mirroring what portal.SubmitHandler did at upload time.
func rescoreOne(archivePath string, opts submission.Options, e portal.Entry, cfg exercise.Config) (scoring.Result, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return scoring.Result{}, err
	}
	defer f.Close()

	archive, err := submission.ValidateArchive(context.Background(), f, opts)
	if err != nil {
		return scoring.Result{}, fmt.Errorf("validating the archive: %w", err)
	}
	meta, err := submission.ValidateMetadata(archive.Metadata)
	if err != nil {
		return scoring.Result{}, fmt.Errorf("validating metadata.json: %w", err)
	}

	// A second pass over the archive, not a rewind of the first: ScanLogs
	// hands out one entry reader at a time and ValidateArchive has already
	// drained them.
	if _, err := f.Seek(0, 0); err != nil {
		return scoring.Result{}, fmt.Errorf("rewinding the archive: %w", err)
	}
	var validatorWindow, sentryWindow scoring.LogWindowCheck
	err = submission.ScanLogs(context.Background(), f, opts, func(name string, logGz io.Reader) error {
		switch name {
		case submission.ValidatorLogFileName:
			validatorWindow = scoring.ScanLogWindow(logGz, cfg)
		case submission.SentryLogFileName:
			sentryWindow = scoring.ScanLogWindow(logGz, cfg)
		}
		return nil
	})
	if err != nil {
		return scoring.Result{}, fmt.Errorf("reading the logs: %w", err)
	}

	genesisMatch, versionSupported := scoring.MetadataChecks(meta, cfg)

	return scoring.Result{
		SubmissionID:     e.ID,
		Scored:           true,
		GenesisMatch:     genesisMatch,
		VersionSupported: versionSupported,
		LogWindow:        validatorWindow,
		SentryLogPresent: archive.SentryLogPresent,
		SentryLogWindow:  sentryWindow,
		// Scored from the recorded submission time, not from now: the
		// upload happened when it happened, and re-scoring must not move
		// anyone between tiers.
		UploadTimeScore: scoring.TieredTimeScore(e.SubmittedAt, cfg),
		// Always 25, for the same reason SubmitHandler sets it so: a
		// schema-invalid metadata.json never produced a stored archive in
		// the first place.
		MetadataScore:   25,
		LogQualityScore: scoring.LogQualityScore(validatorWindow, sentryWindow),
	}, nil
}

// describe summarizes the log-window outcome, so a run that moves a score
// says why rather than only by how much.
func describe(r scoring.Result) string {
	switch {
	case !r.LogWindow.Detected && r.LogWindow.Truncated:
		return "validator log unreadable within the scan budget"
	case !r.LogWindow.Detected:
		return "no timestamps in validator log"
	case r.LogWindow.Truncated:
		return "coverage unverified (scan stopped early)"
	case r.LogWindow.Covered:
		return "window covered"
	default:
		return fmt.Sprintf("window not covered (%s to %s)",
			r.LogWindow.FirstSeen.UTC().Format(time.RFC3339),
			r.LogWindow.LastSeen.UTC().Format(time.RFC3339))
	}
}
