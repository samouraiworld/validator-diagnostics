package portal

import (
	"net/http"

	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
)

// AdminDeleteSubmissionHandler serves DELETE /admin/submissions/{id}:
// removes one submission's log entry, scoring record, and uploaded
// archive together. Register with the "DELETE /admin/submissions/{id}"
// mux pattern so {id} is available via r.PathValue("id"); wrap with
// AdminAuth.
func AdminDeleteSubmissionHandler(log *FileLog, store storage.Store, scores *scoring.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing submission id", http.StatusBadRequest)
			return
		}

		entries, err := log.Entries()
		if err != nil {
			http.Error(w, "unable to read submissions", http.StatusInternalServerError)
			return
		}
		var entry Entry
		found := false
		for _, e := range entries {
			if e.ID == id {
				entry = e
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "unknown submission id", http.StatusNotFound)
			return
		}

		// Delete the archive before any bookkeeping: if this fails, the
		// row stays in the table and the admin can retry, rather than
		// the dashboard showing the submission gone while its archive
		// still exists somewhere with nothing left pointing at it.
		if err := store.Delete(r.Context(), entry.Filename); err != nil {
			http.Error(w, "unable to delete archive: "+err.Error(), http.StatusBadGateway)
			return
		}

		if err := scores.Delete(id); err != nil {
			http.Error(w, "unable to delete scoring record", http.StatusInternalServerError)
			return
		}

		if _, err := log.Delete(id); err != nil {
			http.Error(w, "unable to delete submission log entry", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
