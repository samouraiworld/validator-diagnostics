// Package portal wires the auth, submission, and storage packages
// together into the archive-upload endpoint described in prd.md
// ("Phase 2 — Artifact Collection & Submission"). It is the orchestration
// layer only — the actual auth/validation/storage logic lives in the
// packages it composes.
package portal

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/clamav"
	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
	"github.com/samourai/validator-diagnostics/submission"
)

const (
	// defaultMaxUploadSize is the fallback for a SubmitHandler built
	// without MaxUploadSize — currently only cmd/portal-dev, which wires
	// no AVScanner and no MaxUploadSize at all. The archive is no longer
	// scanned as a file (clamd, when there is one, only ever sees
	// extracted content: metadata.json whole, then the decompressed log
	// in 1 GiB windows), so this value has nothing to do with clamd's
	// StreamMaxLength or libclamav's scan ceiling — matching cmd/portal's
	// defaultMaxUploadSize is just consistency between the production
	// binary and the dev tool, not a scan requirement. Change this and you
	// are changing what an unconfigured handler accepts — see the README
	// section "Upload size and ClamAV".
	defaultMaxUploadSize = 4294967296 // 4 GiB; matches cmd/portal's defaultMaxUploadSize

	// multipartMemoryThreshold is how much of the request Go buffers in
	// memory before spilling additional parts to its own temp files —
	// not a size limit, just a memory/disk trade-off knob.
	multipartMemoryThreshold = 32 << 20
)

// SubmitHandler serves POST /submit: a multipart upload of the fire
// drill archive, authenticated via the session token minted by
// /auth/verify.
type SubmitHandler struct {
	Sessions *auth.SessionSigner
	Store    storage.Store

	// Log records successful submissions for the admin dashboard.
	// Optional — a nil Log disables recording.
	Log Log

	// AVScanner scans the archive's extracted content for malware before
	// it is stored (prd.md, "Security Considerations" — "Run an antivirus
	// scan (e.g. ClamAV) on extracted content").
	//
	// A nil AVScanner disables scanning entirely, and that is a real
	// configuration, not just a test shortcut: cmd/portal-dev runs this
	// way, and cmd/portal does too when -clamav-addr is unset. Nil also
	// means no Entry.Scan is recorded — the dashboard must not vouch for a
	// submission nothing examined.
	AVScanner clamav.Scanner

	// Exercise and Scores wire in the Phase 3 automatic checks and
	// scoring (see the scoring package). A nil Exercise disables
	// scoring entirely, same convention as Log.
	Exercise *exercise.FileStore
	Scores   *scoring.Store

	// ArchiveOptions bounds ValidateArchive's per-entry reads. Zero
	// value uses submission's own defaults.
	ArchiveOptions submission.Options

	// MaxUploadSize caps the whole request body. Zero uses
	// defaultMaxUploadSize.
	MaxUploadSize int64

	// AVScanBudget caps how many decompressed bytes of log content are
	// submitted to the scanner. Zero uses clamav.DefaultScanBudget.
	// Exceeding it is recorded as partial coverage, never a rejection.
	AVScanBudget int64

	// Progress publishes server-side progress for the upload page to poll
	// (see ProgressHandler). Optional — a nil Progress disables reporting
	// and changes nothing else about how a submission is handled.
	Progress *ProgressTracker
}

type submitResponse struct {
	OK          bool   `json:"ok"`
	Moniker     string `json:"moniker,omitempty"`
	SubmittedAt string `json:"submitted_at,omitempty"`
	Error       string `json:"error,omitempty"`
}

// phaseTimer records how long each server-side phase took and logs one
// line per submission.
//
// The ProgressTracker already publishes these same transitions, but only
// live and only to the operator's own browser: nothing survives the
// request. So a submission that took an hour left no record of *where* the
// hour went — scan, store, or somewhere unexpected — which is precisely
// what an operator needs to size -av-scan-budget, the submission limit, and
// clamd's thread pool against real traffic rather than guesses.
//
// It wraps the phase transition rather than sitting beside it so the two
// cannot drift apart: there is one call site for both.
type phaseTimer struct {
	progress *ProgressHandle
	current  Phase
	since    time.Time
	spans    []string
}

func newPhaseTimer(progress *ProgressHandle) *phaseTimer {
	return &phaseTimer{progress: progress}
}

// phase closes the span in progress and opens one for p.
func (t *phaseTimer) phase(p Phase, total int64) {
	t.closeSpan()
	t.current, t.since = p, time.Now()
	t.progress.Phase(p, total)
}

func (t *phaseTimer) closeSpan() {
	if t.current == "" {
		return
	}
	t.spans = append(t.spans, fmt.Sprintf("%s=%s", t.current, time.Since(t.since).Round(time.Millisecond)))
	t.current = ""
}

// log emits the collected spans. Meant to be deferred, so it covers a
// submission that ended early just as well as one that ran to completion —
// a rejected scan still reports how long the scanning phase ran before it
// failed, which is the case most worth measuring.
func (t *phaseTimer) log(filename string) {
	t.closeSpan()
	if len(t.spans) == 0 {
		return
	}
	log.Printf("submission timings for %s: %s", filename, strings.Join(t.spans, " "))
}

// ServeHTTP validates the session, the archive's filename/structure/
// metadata, cross-checks the archive's declared identity against the
// authenticated operator address, and — only if every check passes —
// stores the original uploaded bytes unchanged.
func (h *SubmitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	operatorAddr, err := auth.RequireSession(h.Sessions, r)
	if err != nil {
		writeSubmitResult(w, http.StatusUnauthorized, submitResponse{
			Error: "unauthenticated: complete /auth/challenge and /auth/verify first",
		})
		return
	}

	maxUpload := h.MaxUploadSize
	if maxUpload <= 0 {
		maxUpload = defaultMaxUploadSize
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)

	if err := r.ParseMultipartForm(multipartMemoryThreshold); err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{
			Error: fmt.Sprintf("unable to parse upload (over the %d byte limit, or malformed): %v", maxUpload, err),
		})
		return
	}
	defer r.MultipartForm.RemoveAll()

	// Tracking starts here, not earlier: everything before this was reading
	// the request body, which the browser already observes through its own
	// upload progress events. The page polls from the moment its last byte
	// leaves, so it will see 404s until this line runs — which is correct,
	// and which it treats as "not yet".
	progress := h.Progress.Begin(operatorAddr.String())
	defer progress.Done()

	file, header, err := r.FormFile("archive")
	if err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{Error: `missing "archive" file field`})
		return
	}
	defer file.Close()

	timer := newPhaseTimer(progress)
	defer timer.log(header.Filename)

	moniker, submittedAt, err := submission.ValidateFilename(header.Filename)
	if err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{Error: err.Error()})
		return
	}

	// file (a multipart.File) is always Seek-able, whether Go held it
	// in memory or spilled it to a temp file above — so ValidateArchive,
	// the AV scan, and Store.Save can each take their own full pass
	// over it without us buffering a second copy ourselves.
	timer.phase(PhaseValidating, 0)
	archiveResult, err := submission.ValidateArchive(r.Context(), file, h.ArchiveOptions)
	if err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{Error: err.Error()})
		return
	}

	metadata, err := submission.ValidateMetadata(archiveResult.Metadata)
	if err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{Error: err.Error()})
		return
	}

	// The whole point of the challenge-tx auth is proving ownership of
	// the operator address (prd.md, "Authentication" — "proving
	// ownership of the validator identity"); a mismatch here means
	// metadata.json's claimed identity isn't backed by that proof.
	if metadata.ValidatorAddress != operatorAddr.String() {
		writeSubmitResult(w, http.StatusForbidden, submitResponse{
			Error: "metadata.json validator_address does not match the authenticated operator address",
		})
		return
	}
	if metadata.Moniker != moniker {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{
			Error: "metadata.json moniker does not match the archive filename",
		})
		return
	}

	// scanCoverage is nil unless a scanner actually ran: see Entry.Scan.
	var scanCoverage *clamav.Coverage

	if h.AVScanner != nil {
		timer.phase(PhaseScanning, 0)
		// Always wrapped: Add on a nil handle is a no-op, so this needs no
		// guard for a handler built without a tracker.
		scanner := countingScanner{inner: h.AVScanner, add: progress.Add}
		verdict, coverage, err := scanArchive(r.Context(), file, h.ArchiveOptions, archiveResult.Metadata, scanner, h.AVScanBudget)
		switch {
		case errors.Is(err, errUnreadableLog):
			// ValidateArchive only checked each log entry's two magic
			// bytes, so a log that cannot be decompressed at all gets this
			// far. Nothing in it was ever readable, so nothing in it can be
			// scanned, and storing it would be exactly the fail-open the
			// AV step exists to prevent.
			writeSubmitResult(w, http.StatusBadRequest, submitResponse{
				Error: fmt.Sprintf("a log entry could not be decompressed, so it could not be scanned: %v", err),
			})
			return
		case err != nil:
			log.Printf("antivirus scan for %s failed: %v", header.Filename, err)
			writeSubmitResult(w, http.StatusServiceUnavailable, submitResponse{
				Error: "antivirus scan unavailable, please try again shortly",
			})
			return
		}
		if verdict.Infected {
			writeSubmitResult(w, http.StatusUnprocessableEntity, submitResponse{
				Error: fmt.Sprintf("archive rejected: malware detected (%s)", verdict.Signature),
			})
			return
		}
		if !coverage.Complete {
			// Accepted, but never silently: the budget running out and the
			// log's stream breaking are the only two incomplete outcomes,
			// and Bytes against the budget says which one happened.
			log.Printf("antivirus coverage incomplete for %s: %d bytes scanned (budget %d)",
				header.Filename, coverage.Bytes, h.avScanBudget())
		}
		scanCoverage = &coverage
	}

	submissionID, err := NewSubmissionID()
	if err != nil {
		writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to prepare submission record"})
		return
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to rewind upload"})
		return
	}

	// file is seekable (see the comment above ValidateArchive) and
	// storage.S3Store.Save depends on that — its checksum middleware
	// requires a seekable body over plain HTTP, and its retry middleware
	// rewinds one after a transient failure — so this is wrapped in
	// countingSeeker, which forwards Seek, not the plain countingReader
	// the antivirus path above uses for its genuinely non-seekable gzip
	// stream.
	timer.phase(PhaseStoring, header.Size)
	if err := h.Store.Save(r.Context(), header.Filename, &countingSeeker{r: file, add: progress.Add}, header.Size); err != nil {
		writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to store archive"})
		return
	}

	// One server-side timestamp for the whole submission: the score and
	// the logged entry describe the same event, and two separate
	// time.Now() calls can straddle a tier boundary, leaving a recorded
	// SubmittedAt that doesn't justify the UploadTimeScore stored beside
	// it. Distinct from submittedAt above, which is the validator's own
	// declared time parsed out of the filename and only echoed back.
	recordedAt := time.Now().UTC()

	if h.Exercise != nil {
		timer.phase(PhaseScoring, 0)
		cfg, err := h.Exercise.Get()
		if err != nil {
			log.Printf("scoring: unable to read exercise config for %s: %v", header.Filename, err)
		} else {
			result := scoring.Result{SubmissionID: submissionID}
			if cfg.Configured() {
				// The archive is already stored (Store.Save above) by
				// the time this runs, so scoring is organizer-side
				// work, not something the validator's own request
				// should be able to cut short: a validator who closes
				// their browser during the "server is scanning" phase
				// — which the UI explicitly says can take several
				// minutes — must not leave the archive stored but
				// permanently unscored. WithoutCancel keeps
				// request-scoped values but drops cancellation, so
				// this call runs to completion regardless of client
				// disconnect.
				scoringCtx := context.WithoutCancel(r.Context())
				genesisMatch, versionSupported, windows, err := autoChecks(scoringCtx, file, h.ArchiveOptions, metadata, cfg)
				if err != nil {
					// The archive is already stored and the validator has
					// their submission; a scoring read that fails here is
					// an organizer-side problem, so it is logged and the
					// result stays unscored rather than failing the
					// request. Same reasoning as the Exercise.Get failure
					// handled just above.
					log.Printf("scoring: unable to read the log for %s: %v", header.Filename, err)
				} else {
					// Scored is set here, not before the checks: a
					// Scored: true record carrying zero-valued checks
					// would claim a submission was assessed when the read
					// that would have assessed it failed.
					result.Scored = true
					result.GenesisMatch = genesisMatch
					result.VersionSupported = versionSupported
					result.LogWindow = windows.validator
					result.SentryLogPresent = archiveResult.SentryLogPresent
					result.SentryLogWindow = windows.sentry
					result.UploadTimeScore = scoring.TieredTimeScore(recordedAt, cfg)
					// Always 25: ValidateMetadata above already gated this
					// submission on a schema-valid metadata.json, so by the
					// time a Result exists at all, this criterion is
					// structurally satisfied — see scoring.LogQualityScore's
					// doc comment for the analogous reasoning on log quality.
					result.MetadataScore = 25
					result.LogQualityScore = scoring.LogQualityScore(windows.validator, windows.sentry)
				}
			}
			if h.Scores != nil {
				if err := h.Scores.Set(result); err != nil {
					log.Printf("scoring: unable to record result for %s: %v", header.Filename, err)
				}
			}
		}
	}

	if h.Log != nil {
		entry := Entry{
			ID:              submissionID,
			Moniker:         moniker,
			OperatorAddress: operatorAddr.String(),
			Filename:        header.Filename,
			SubmittedAt:     recordedAt,
			SentryEnabled:   metadata.SentryEnabled,
			Scan:            scanCoverage,
		}
		if err := h.Log.Record(r.Context(), entry); err != nil {
			// The archive is already safely stored — a logging failure
			// shouldn't fail the submission from the validator's point
			// of view, but organizers should still be able to see it
			// happened.
			log.Printf("submission log: unable to record entry for %s: %v", header.Filename, err)
		}
	}

	writeSubmitResult(w, http.StatusOK, submitResponse{
		OK:          true,
		Moniker:     moniker,
		SubmittedAt: submittedAt.UTC().Format("2006-01-02T15:04Z"),
	})
}

func writeSubmitResult(w http.ResponseWriter, status int, resp submitResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// logWindows carries one window check per log entry. A struct rather
// than two more return values: autoChecks already returns four things,
// and the two windows are read together everywhere they are read at all.
type logWindows struct {
	validator scoring.LogWindowCheck
	sentry    scoring.LogWindowCheck
}

// autoChecks runs the Phase 3 automatic checks against the log entries
// inside file, streaming each straight out of the archive rather than
// holding it in memory. file must be the already-validated upload; it is
// rewound first, so callers must not rely on its offset afterwards.
//
// One ScanLogs walk covers both logs. Opening them separately would
// decompress the outer gzip once per entry, over an archive that may run
// to gigabytes.
func autoChecks(ctx context.Context, file io.ReadSeeker, opts submission.Options, meta submission.Metadata, cfg exercise.Config) (genesisMatch, versionSupported bool, windows logWindows, err error) {
	genesisMatch, versionSupported = scoring.MetadataChecks(meta, cfg)

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false, false, logWindows{}, fmt.Errorf("rewinding upload: %w", err)
	}

	err = submission.ScanLogs(ctx, file, opts, func(name string, logGz io.Reader) error {
		switch name {
		case submission.ValidatorLogFileName:
			windows.validator = scoring.ScanLogWindow(logGz, cfg)
		case submission.SentryLogFileName:
			windows.sentry = scoring.ScanLogWindow(logGz, cfg)
		}
		return nil
	})
	if err != nil {
		return false, false, logWindows{}, err
	}

	return genesisMatch, versionSupported, windows, nil
}

// errUnreadableLog marks a log entry whose gzip stream could not be
// opened at all. It is distinct from a scanner failure because the two
// are answered differently: this is the submitter's problem (400), a
// scanner failure is ours (503). It applies to the optional sentry log
// as much as the required validator log — an entry that is stored
// without ever being scanned is the fail-open the AV step exists to
// prevent, whether or not the entry had to be there.
var errUnreadableLog = errors.New("not a readable gzip stream")

// errInfected stops the ScanLogs walk on the first infected verdict.
// Internal to scanArchive: the verdict itself travels in a variable, not
// in the error.
var errInfected = errors.New("infected")

// scanArchive submits the archive's extracted content to scanner: first
// metadata.json, already in memory and small enough to scan whole, then
// each decompressed log in windows, all sharing one budget.
//
// clamd never sees the raw .tar.gz. libclamav refuses to scan any single
// file of 2 GiB or more, and that ceiling applies to every file it
// extracts — including the decompressed logs — so the archive is taken
// apart here instead, which is also what prd.md asks for ("Run an
// antivirus scan on extracted content").
//
// budget is per submission, not per log: it bounds how much decompressed
// content one submission may cost the antivirus, and giving each entry
// its own copy would silently double that ceiling. A log reached with
// nothing left is not scanned, not counted, and forces incomplete
// coverage — never scanned under a fresh budget, which is what handing
// WindowedScanner a non-positive Budget would quietly do.
//
// file must be the already-validated upload; it is rewound first, so
// callers must not rely on its offset afterwards.
func scanArchive(ctx context.Context, file io.ReadSeeker, opts submission.Options, metadata []byte, scanner clamav.Scanner, budget int64) (clamav.Verdict, clamav.Coverage, error) {
	verdict, err := scanner.Scan(ctx, bytes.NewReader(metadata))
	if err != nil {
		return clamav.Verdict{}, clamav.Coverage{}, fmt.Errorf("scanning %s: %w", submission.MetadataFileName, err)
	}
	if verdict.Infected {
		return verdict, clamav.Coverage{}, nil
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return clamav.Verdict{}, clamav.Coverage{}, fmt.Errorf("rewinding upload: %w", err)
	}

	if budget <= 0 {
		budget = clamav.DefaultScanBudget
	}
	remaining := budget

	// Complete starts true and is only ever cleared: it is an assertion
	// about every log, so one incomplete entry settles it for the archive.
	coverage := clamav.Coverage{Complete: true}
	var infected clamav.Verdict

	err = submission.ScanLogs(ctx, file, opts, func(name string, logGz io.Reader) error {
		if remaining <= 0 {
			coverage.Complete = false
			return nil
		}

		gz, err := gzip.NewReader(logGz)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", errUnreadableLog, name, err)
		}
		defer gz.Close()

		v, c, err := clamav.WindowedScanner{Scanner: scanner, Budget: remaining}.ScanStream(ctx, gz)
		if err != nil {
			return err
		}

		coverage.Bytes += c.Bytes
		coverage.Complete = coverage.Complete && c.Complete
		remaining -= c.Bytes

		if v.Infected {
			infected = v
			return errInfected
		}
		return nil
	})

	switch {
	case errors.Is(err, errInfected):
		return infected, coverage, nil
	case err != nil:
		return clamav.Verdict{}, clamav.Coverage{}, err
	}

	return clamav.Verdict{}, coverage, nil
}

// avScanBudget is the effective budget, for logging: WindowedScanner applies
// the same fallback internally.
func (h *SubmitHandler) avScanBudget() int64 {
	if h.AVScanBudget <= 0 {
		return clamav.DefaultScanBudget
	}
	return h.AVScanBudget
}
