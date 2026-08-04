package portal

import (
	"crypto/subtle"
	"encoding/json"
	"log"
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

	// TotalScore and Pending are computed here rather than in the
	// dashboard's JavaScript so the rubric has exactly one
	// implementation: scoring.Result's own. TotalScore is 0 and Pending
	// is true whenever Score is nil or unscored — nothing has been
	// awarded yet in that case.
	TotalScore int  `json:"total_score"`
	Pending    bool `json:"pending"`
}

// AdminSubmissionsHandler serves the recorded submissions, joined with
// their scoring records, as a JSON array. Wrap it with AdminAuth.
func AdminSubmissionsHandler(submissionLog *FileLog, scores *scoring.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		entries, err := submissionLog.Entries()
		if err != nil {
			http.Error(w, "unable to read submissions", http.StatusInternalServerError)
			return
		}

		out := make([]AdminSubmission, 0, len(entries))
		for _, e := range entries {
			sub := AdminSubmission{Entry: e, Pending: true}

			result, ok, err := scores.Get(e.ID)
			if err != nil {
				// Not the same thing as "no score yet": the store itself
				// is unreadable, so every row's score is unknown, not
				// pending. Rendering that as a dashboard full of "pending"
				// would hide, say, a corrupted scores.json indefinitely.
				log.Printf("admin: unable to read scoring record for %s: %v", e.ID, err)
				http.Error(w, "unable to read scoring records — the scores file may be missing or corrupt; see the portal server log", http.StatusInternalServerError)
				return
			}
			if ok {
				sub.Score = &result
				// Only a record with an automatic half has a total worth
				// showing. Summing the manual fields of an unscored record
				// would report, say, 25/100 as final while none of the
				// automatic points were ever computed.
				if result.Scored {
					sub.TotalScore = result.TotalScore()
					sub.Pending = result.Pending()
				}
			}
			out = append(out, sub)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}
