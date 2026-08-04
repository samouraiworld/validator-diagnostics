package portal

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/samourai/validator-diagnostics/scoring"
)

// AdminAuth wraps next with HTTP Basic Auth, checking only the password
// (any username is accepted) against a single admin password. The
// comparison is constant-time to avoid a timing side-channel on the
// password check.
func AdminAuth(password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="validator-fire-drill-admin"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AdminSubmission is one row of the admin dashboard: a recorded
// submission joined with its Phase 3 scoring record, if one exists yet
// (Score is nil before a submission has been auto-scored — see
// SubmitHandler's Exercise/Scores wiring).
type AdminSubmission struct {
	Entry
	Score *scoring.Result `json:"score,omitempty"`
}

// AdminSubmissionsHandler serves the recorded submissions, joined with
// their scoring records, as a JSON array. Wrap it with AdminAuth.
func AdminSubmissionsHandler(log *FileLog, scores *scoring.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		entries, err := log.Entries()
		if err != nil {
			http.Error(w, "unable to read submissions", http.StatusInternalServerError)
			return
		}

		out := make([]AdminSubmission, 0, len(entries))
		for _, e := range entries {
			sub := AdminSubmission{Entry: e}
			if result, ok, err := scores.Get(e.ID); err == nil && ok {
				sub.Score = &result
			}
			out = append(out, sub)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}
