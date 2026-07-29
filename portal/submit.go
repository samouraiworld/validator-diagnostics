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
	"net/http"

	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/storage"
	"github.com/samourai/validator-diagnostics/submission"
)

const (
	// defaultMaxUploadSize matches prd.md's "Maximum upload size (for
	// example 10 GB)".
	defaultMaxUploadSize = 10 << 30

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
	// in memory or spilled it to a temp file above — so ValidateArchive
	// and Store.Save can each take their own full pass over it without
	// us buffering a second copy ourselves.
	result, err := submission.ValidateArchive(r.Context(), file, h.ArchiveOptions)
	if err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{Error: err.Error()})
		return
	}

	metadata, err := submission.ValidateMetadata(result.Metadata)
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

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to rewind upload"})
		return
	}

	if err := h.Store.Save(r.Context(), header.Filename, file, header.Size); err != nil {
		writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to store archive"})
		return
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
