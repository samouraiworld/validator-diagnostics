package portal

import (
	"net/http"
	"strconv"
	"time"
)

// LimitSubmissions bounds how many submissions run inside next at once.
//
// A submission is not a cheap unit of work: it spills the whole archive to
// a temp file for its entire duration, walks that file three times
// (ValidateArchive, scanArchive, autoChecks) decompressing the outer gzip
// each time, and streams the decompressed logs through clamd — which spools
// every INSTREAM window to its own disk before scanning it. Past a handful
// in parallel those costs stop overlapping and start competing, for disk
// bandwidth and for clamd's thread pool.
//
// Serialising is what keeps total throughput up rather than what caps it.
// The case that makes this load-bearing rather than merely tidy is
// ClamdScanner's per-scan timeout: it is wall-clock and covers the dial, so
// sharing clamd between many submissions stretches every window towards it.
// Enough concurrency and windows start timing out, which is a failed scan —
// a 503 that rejects the submission outright, after all the work.
//
// A request that cannot get a slot waits up to wait for one, then gets a
// 503 with Retry-After rather than queueing indefinitely. That is the
// kinder failure: a validator stalled behind a full queue sees nothing at
// all — their body is filling a socket buffer nobody is draining, so even
// the browser's own upload bar freezes with no explanation — whereas a
// rejection names a delay they can act on. The reply is the same JSON shape
// every other /submit answer uses, because the upload page parses the body
// before it looks at the status.
//
// n <= 0 disables the limit and returns next unchanged.
func LimitSubmissions(n int, wait time.Duration, next http.Handler) http.Handler {
	if n <= 0 {
		return next
	}
	sem := make(chan struct{}, n)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(wait)
		defer timer.Stop()

		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)

		case <-timer.C:
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
			writeSubmitResult(w, http.StatusServiceUnavailable, submitResponse{
				Error: "too many submissions are being processed right now; please retry in a few minutes",
			})

		case <-r.Context().Done():
			// The client gave up while waiting. The connection is gone, so
			// there is nothing to write and no slot was ever taken.
		}
	})
}
