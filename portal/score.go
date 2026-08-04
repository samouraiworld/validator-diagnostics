package portal

import (
	"encoding/json"
	"mime"
	"net/http"

	"github.com/samourai/validator-diagnostics/scoring"
)

// scoreRequest is decoded from POST /admin/submissions/{id}/score's
// body. IncidentResponseQualityScore is a pointer so that an omitted or
// null field is distinguishable from a deliberate 0 — which is itself a
// valid score. Decoding a missing score to 0 would flip
// Result.Pending() to false and present a fabricated total as final.
type scoreRequest struct {
	IncidentResponseQualityScore *int `json:"incident_response_quality_score"`
}

// AdminScoreHandler serves POST /admin/submissions/{id}/score: the
// admin's manual entry for the one rubric criterion that can't be
// computed automatically (prd.md "Evaluation Criteria" — incident
// response quality). Register with the
// "POST /admin/submissions/{id}/score" mux pattern so {id} is
// available via r.PathValue("id"); wrap with AdminAuth.
func AdminScoreHandler(log *FileLog, scores *scoring.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing submission id", http.StatusBadRequest)
			return
		}

		// CSRF defence: without this, a cross-site
		// <form enctype="text/plain"> POST is a CORS "simple request"
		// that needs no preflight, so the browser would attach the
		// admin's cached Basic credentials and this handler would decode
		// the JSON-shaped body it can produce. Requiring
		// application/json makes the request non-simple, forcing a
		// preflight that this server (sending no
		// Access-Control-Allow-Origin) never approves.
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}

		var req scoreRequest
		dec := json.NewDecoder(r.Body)
		// Reject unknown fields, matching submission.ValidateMetadata: a
		// misspelt score key would otherwise be silently dropped and stored
		// as the zero value.
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.IncidentResponseQualityScore == nil {
			http.Error(w, "incident_response_quality_score is required", http.StatusBadRequest)
			return
		}
		if *req.IncidentResponseQualityScore < 0 || *req.IncidentResponseQualityScore > 25 {
			http.Error(w, "incident_response_quality_score must be between 0 and 25", http.StatusBadRequest)
			return
		}

		entries, err := log.Entries()
		if err != nil {
			http.Error(w, "unable to read submissions", http.StatusInternalServerError)
			return
		}
		found := false
		for _, e := range entries {
			if e.ID == id {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "unknown submission id", http.StatusNotFound)
			return
		}

		result, ok, err := scores.Get(id)
		if err != nil {
			http.Error(w, "unable to read scoring record", http.StatusInternalServerError)
			return
		}
		// A manual score completes an automatic half; it doesn't stand in
		// for one. A submission recorded before the exercise was
		// configured has no automatic half and can never acquire one —
		// AutoChecks needs the log bytes, which aren't retained past the
		// request. Writing the manual field onto it would clear
		// Pending() while the automatic scores stayed at zero, publishing
		// a total that reads as final and means nothing.
		if !ok || !result.Scored {
			http.Error(w, "submission was never auto-scored (it arrived before the exercise was configured), so it cannot be scored manually", http.StatusConflict)
			return
		}
		result.SubmissionID = id
		irq := *req.IncidentResponseQualityScore
		result.IncidentResponseQualityScore = &irq

		if err := scores.Set(result); err != nil {
			http.Error(w, "unable to save score", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}
