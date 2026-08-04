package exercise

import (
	"encoding/json"
	"mime"
	"net/http"
)

// requireJSONContentType rejects anything that isn't application/json
// (an optional charset parameter is fine), and reports whether the
// request may proceed.
//
// This is the CSRF defence for a state-changing endpoint that sits
// behind HTTP Basic Auth: a cross-site
// <form enctype="text/plain"> POST is a CORS "simple request", so it
// needs no preflight and the browser attaches the admin's cached
// credentials to it — and a JSON decoder is perfectly happy to decode
// the JSON-shaped body such a form can produce. Insisting on
// application/json makes the request non-simple, which forces a
// preflight this server never approves (it sends no
// Access-Control-Allow-Origin), so the browser blocks it.
func requireJSONContentType(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

// ConfigHandler serves GET (current config) and POST (replace it) on
// the same route. Wrap with portal.AdminAuth at the caller — this
// handler does no authentication of its own.
func ConfigHandler(store *FileStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg, err := store.Get()
			if err != nil {
				http.Error(w, "unable to read exercise config", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)

		case http.MethodPost:
			if !requireJSONContentType(w, r) {
				return
			}
			var cfg Config
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := store.Set(cfg); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
