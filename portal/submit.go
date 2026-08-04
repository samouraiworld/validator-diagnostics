// Package portal wires the auth, submission, and storage packages
// together into the archive-upload endpoint described in prd.md
// ("Phase 2 — Artifact Collection & Submission"). It is the orchestration
// layer only — the actual auth/validation/storage logic lives in the
// packages it composes.
package portal

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	// without MaxUploadSize. Deliberately below prd.md's "for example
	// 10 GB": with an AV scanner wired in, anything above clamd's
	// StreamMaxLength is guaranteed to 503, and cmd/portal and
	// clamd.conf both standardise on 2 GiB. Change this and you are
	// changing what an unconfigured handler accepts but clamd won't
	// scan — see the README section "Upload size and ClamAV".
	defaultMaxUploadSize = 2 << 30

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

	// AVScanner scans uploaded archives for malware before they're
	// stored (prd.md, "Security Considerations" — ClamAV defense in
	// depth). A nil AVScanner disables scanning; cmd/portal always
	// wires clamav.NoopScanner explicitly instead of leaving this nil,
	// so nil only shows up in tests that don't care about the AV step.
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
}

type submitResponse struct {
	OK          bool   `json:"ok"`
	Moniker     string `json:"moniker,omitempty"`
	SubmittedAt string `json:"submitted_at,omitempty"`
	Error       string `json:"error,omitempty"`
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

	file, header, err := r.FormFile("archive")
	if err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{Error: `missing "archive" file field`})
		return
	}
	defer file.Close()

	moniker, submittedAt, err := submission.ValidateFilename(header.Filename)
	if err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{Error: err.Error()})
		return
	}

	// file (a multipart.File) is always Seek-able, whether Go held it
	// in memory or spilled it to a temp file above — so ValidateArchive,
	// the AV scan, and Store.Save can each take their own full pass
	// over it without us buffering a second copy ourselves.
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

	if h.AVScanner != nil {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to rewind upload"})
			return
		}
		verdict, err := h.AVScanner.Scan(r.Context(), file)
		if err != nil {
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

	if err := h.Store.Save(r.Context(), header.Filename, file, header.Size); err != nil {
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
		cfg, err := h.Exercise.Get()
		if err != nil {
			log.Printf("scoring: unable to read exercise config for %s: %v", header.Filename, err)
		} else {
			result := scoring.Result{SubmissionID: submissionID}
			if cfg.Configured() {
				genesisMatch, versionSupported, window := scoring.AutoChecks(metadata, archiveResult.LogGz, cfg)
				result.Scored = true
				result.GenesisMatch = genesisMatch
				result.VersionSupported = versionSupported
				result.LogWindow = window
				result.UploadTimeScore = scoring.TieredTimeScore(recordedAt, cfg)
				// Always 20: ValidateMetadata above already gated this
				// submission on a schema-valid metadata.json, so by the
				// time a Result exists at all, this criterion is
				// structurally satisfied — see scoring.LogQualityScore's
				// doc comment for the analogous reasoning on log quality.
				result.MetadataScore = 20
				result.LogQualityScore = scoring.LogQualityScore(window)
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
