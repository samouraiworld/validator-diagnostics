package portal

import (
	"crypto/subtle"
	"net/http"
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
