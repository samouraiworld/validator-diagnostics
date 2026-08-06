// Command portal is the validator fire drill submission portal: the
// challenge-tx auth endpoints, the archive upload endpoint, the admin
// submissions dashboard, and the static frontend, all in one binary.
//
// Storage backend: pass either -upload-dir (local disk, for testing) or
// -s3-bucket (+ -s3-region/-s3-endpoint, with credentials from the
// S3_ACCESS_KEY/S3_SECRET_KEY environment variables) for production.
//
// The archive's *extracted content* — metadata.json whole, then the
// decompressed gnoland.log.gz in 1 GiB windows — is streamed to clamd for
// a malware scan before being stored, when -clamav-addr is set; the scan
// still fails closed. clamd's own StreamMaxLength (the bundled clamd.conf
// sets it to 2147483647) now only has to cover one window plus its 1 MiB
// overlap, not the whole -max-upload-size archive.
//
// Required environment variables:
//   - ADMIN_OPERATOR_ADDRESSES — comma-separated bech32 operator
//     addresses allowed to authenticate against every admin data route:
//     /admin/submissions, /admin/exercise,
//     /admin/submissions/{id}/score, /admin/submissions/{id} (DELETE),
//     and /admin/summary. (GET /admin itself is unauthenticated: it is
//     the sign-in page, and a browser navigating to it cannot attach an
//     Authorization header.) Admins sign in the same challenge-tx way
//     validators do (see /auth/challenge, /auth/admin/verify) — an
//     address not in this list gets a 403 even with a valid signature.
//   - SESSION_SECRET (optional) — hex-encoded HMAC secret for validator
//     upload session tokens. If unset, a random one is generated for
//     this run (sessions won't survive a restart — fine for a single
//     exercise, not for a long-lived deployment).
//   - ADMIN_SESSION_SECRET (optional) — same as SESSION_SECRET, for the
//     separate admin session tokens, so restarting the portal doesn't
//     also invalidate in-flight validator upload sessions (or vice
//     versa).
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/clamav"
	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
	"github.com/samourai/validator-diagnostics/submission"
)

//go:embed static
var staticFiles embed.FS

// defaultMaxUploadSize is the accepted-upload ceiling this deployment
// standardises on, and it is deliberately *not* prd.md's "for example
// 10 GB". 4294967296 (4 GiB) replaces a prior 2147483647 (2 GiB - 1) that
// was inherited from when the whole archive was streamed to clamd and
// libclamav's own scan ceiling bound it directly (see clamd.conf's comment
// on StreamMaxLength for that ceiling — it's still real, it just doesn't
// reach this flag anymore): clamd now only ever sees extracted content in
// 1 GiB windows, so the old value was outliving its justification. It was
// raised because a real archive needed it:
// test/samourai-crew-huge-*.tar.gz, the archive the windowed-scan feature
// exists for, is 2406610464 bytes, and the old ceiling rejected it via
// http.MaxBytesReader before ValidateArchive ever ran.
//
// 4 GiB stays comfortably under storage.S3Store.Save's single PutObject,
// which S3 caps at 5 GiB. The cost of raising it further is disk, not
// clamd or S3: portal.SubmitHandler's multipart form spills past 32 MiB to
// a temp file, so free disk per concurrent submission has to cover roughly
// the archive size — see README.md's "Upload size and ClamAV".
//
// This is the source of truth for MAX_UPLOAD_SIZE's default in
// .env.example and docker-compose.yml, which hardcode the same number
// because they cannot import a Go constant; keep all three in step.
const defaultMaxUploadSize = 4294967296 // 4 GiB; see README.md's "Upload size and ClamAV"

// defaultMaxLogSize caps the gnoland.log.gz entry inside the archive.
// submission's own default is 2 GiB; this deployment now matches
// defaultMaxUploadSize instead of standardising lower, because a real
// submission needs the headroom:
// test/samourai-crew-huge-*.tar.gz's gnoland.log.gz entry alone is
// 2423361333 bytes compressed, well past the previous 256 MiB ceiling.
//
// The entry is streamed and never buffered (see submission.ValidateArchive
// and submission.OpenLog), so this bounds *compressed* bytes read out of
// the archive rather than resident memory. Two separate bounds apply to the
// *decompressed* bytes: scoring.maxLogWindowBytes (1 GiB) for the log-window
// scan, and -av-scan-budget (32 GiB) for the antivirus.
//
// Raise it with -max-log-size (MAX_LOG_SIZE in .env) if real submissions
// bump into it — they are rejected with a clear message when they do.
// README.md's "Upload size and ClamAV" lists what else has to move with it.
//
// This is the source of truth for MAX_LOG_SIZE's default in .env.example
// and docker-compose.yml, which hardcode the same number because they
// cannot import a Go constant; keep all three in step.
const defaultMaxLogSize = 4294967296 // 4 GiB; see README.md's "Upload size and ClamAV"

func main() {
	remote := flag.String("remote", "", "gno.land RPC endpoint to verify operator pubkeys against, e.g. https://rpc.test13.testnets.gno.land:443")
	addr := flag.String("addr", "localhost:8080", "address to listen on")
	sessionTTL := flag.Duration("session-ttl", 5*time.Minute, "how long an issued validator upload session token stays valid")
	adminSessionTTL := flag.Duration("admin-session-ttl", time.Hour, "how long an issued admin session token stays valid")
	uploadDir := flag.String("upload-dir", "", "local directory to save submitted archives into (use this OR the -s3-* flags)")
	s3Bucket := flag.String("s3-bucket", "", "S3-compatible bucket to save submitted archives into")
	s3Region := flag.String("s3-region", "", "S3-compatible region")
	s3Endpoint := flag.String("s3-endpoint", "", "S3-compatible endpoint (leave empty for real AWS S3)")
	logPath := flag.String("log-path", "./submissions.jsonl", "path to the submission log file, read by the admin dashboard")
	exercisePath := flag.String("exercise-path", "./exercise.json", "path to the Phase 3 exercise config file, managed via POST /admin/exercise")
	scoresPath := flag.String("scores-path", "./scores.json", "path to the Phase 3 scoring records file")
	clamavAddr := flag.String("clamav-addr", "", "clamd address to scan uploads against (host:port, or unix:/path/to/socket); leave empty to disable AV scanning (NOT recommended for production)")
	clamavTimeout := flag.Duration("clamav-timeout", 15*time.Minute, "how long a single clamd scan may take, dial included; bounds one scan window now (at most 1 GiB, roughly 7s at the measured rate), not the whole upload")
	maxUploadSize := flag.Int64("max-upload-size", defaultMaxUploadSize, "maximum accepted upload size in bytes; clamd never sees more than a 1 GiB window of it at a time, so raising this is a storage/time question, not a clamd one (storage.S3Store.Save's single PutObject caps at 5 GiB)")
	maxLogSize := flag.Int64("max-log-size", defaultMaxLogSize, "maximum accepted size in bytes of the gnoland.log.gz entry inside the archive; the entry is streamed rather than buffered, so this bounds decompression work rather than memory")
	avScanBudget := flag.Int64("av-scan-budget", clamav.DefaultScanBudget, "maximum decompressed bytes of gnoland.log.gz submitted to the antivirus; a submission that exceeds it is accepted and recorded as partially scanned, not rejected")
	flag.Parse()

	if *remote == "" {
		log.Fatal("-remote is required (see docs/resources/gnoland-networks.md in gnolang/gno for known endpoints)")
	}

	adminAllowlist, err := parseAdminAllowlist(os.Getenv("ADMIN_OPERATOR_ADDRESSES"))
	if err != nil {
		log.Fatalf("invalid ADMIN_OPERATOR_ADDRESSES: %v", err)
	}

	store, err := configureStore(*uploadDir, *s3Bucket, *s3Region, *s3Endpoint)
	if err != nil {
		log.Fatalf("unable to configure storage: %v", err)
	}

	sessionSecret, err := loadOrGenerateSecret("SESSION_SECRET")
	if err != nil {
		log.Fatalf("unable to prepare session secret: %v", err)
	}
	sessions := auth.NewSessionSigner(sessionSecret, *sessionTTL)

	adminSessionSecret, err := loadOrGenerateSecret("ADMIN_SESSION_SECRET")
	if err != nil {
		log.Fatalf("unable to prepare admin session secret: %v", err)
	}
	adminSessions := auth.NewSessionSigner(adminSessionSecret, *adminSessionTTL)

	nonces := auth.NewNonceStore()
	verifier := &auth.Verifier{Remote: *remote, Nonces: nonces}
	submissionLog := portal.NewFileLog(*logPath)
	exerciseStore := exercise.NewFileStore(*exercisePath)
	scoresStore := scoring.NewStore(*scoresPath)

	avScanner := configureAVScanner(*clamavAddr, *clamavTimeout)

	// One tracker for the process: it holds at most one entry per operator
	// with a submission in flight.
	progressTracker := portal.NewProgressTracker()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("unable to load embedded static assets: %v", err)
	}

	mux := newMux(muxDeps{
		Verifier:        verifier,
		Nonces:          nonces,
		Sessions:        sessions,
		AdminSessions:   adminSessions,
		AdminAllowlist:  adminAllowlist,
		Store:           store,
		SubmissionLog:   submissionLog,
		ExerciseStore:   exerciseStore,
		ScoresStore:     scoresStore,
		AVScanner:       avScanner,
		AVScanBudget:    *avScanBudget,
		MaxUploadSize:   *maxUploadSize,
		ArchiveOptions:  submission.Options{MaxLogSize: *maxLogSize},
		ProgressTracker: progressTracker,
		StaticFS:        staticFS,
	})

	log.Printf("listening on %s, verifying operator pubkeys against %s", *addr, *remote)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// muxDeps groups every dependency newMux needs to wire the portal's
// routes. Extracted from main() so the routing table itself — not just
// individual middleware in isolation — can be exercised by a real HTTP
// round trip in tests.
type muxDeps struct {
	Verifier        *auth.Verifier
	Nonces          *auth.NonceStore
	Sessions        *auth.SessionSigner
	AdminSessions   *auth.SessionSigner
	AdminAllowlist  map[string]bool
	Store           storage.Store
	SubmissionLog   *portal.FileLog
	ExerciseStore   *exercise.FileStore
	ScoresStore     *scoring.Store
	AVScanner       clamav.Scanner
	AVScanBudget    int64
	MaxUploadSize   int64
	ArchiveOptions  submission.Options
	ProgressTracker *portal.ProgressTracker
	StaticFS        fs.FS
}

// newMux builds the portal's routing table.
//
// Two things here are load-bearing and easy to break by accident:
//
//   - /auth/verify and /auth/admin/verify run the same verification
//     logic but mint tokens with *different* signers, so a validator
//     upload session can never be used as an admin session (and vice
//     versa). The /auth/challenge endpoint is shared: nonces are
//     single-use and address-bound regardless of which signer ends up
//     consuming the resulting signature.
//   - GET /admin is deliberately unauthenticated — it serves the admin
//     sign-in page, which a browser cannot request with an
//     Authorization header. Every /admin/* data route stays gated.
func newMux(d muxDeps) *http.ServeMux {
	assets := newStaticAssets(d.StaticFS)

	mux := http.NewServeMux()
	mux.Handle("/auth/challenge", auth.ChallengeHandler(d.Nonces))
	mux.Handle("/auth/verify", auth.VerifyHandler(d.Verifier, d.Sessions))
	mux.Handle("/auth/admin/verify", auth.VerifyHandler(d.Verifier, d.AdminSessions))
	mux.Handle("/submit", submitHandlerFor(d))
	mux.Handle("/submit/progress", portal.ProgressHandler(d.Sessions, d.ProgressTracker))
	mux.Handle("/admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assets.serveFile(w, r, "admin.html")
	}))
	mux.Handle("/admin/submissions", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, portal.AdminSubmissionsHandler(d.SubmissionLog, d.ScoresStore)))
	mux.Handle("/admin/exercise", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, exercise.ConfigHandler(d.ExerciseStore)))
	mux.Handle("POST /admin/submissions/{id}/score", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, portal.AdminScoreHandler(d.SubmissionLog, d.ScoresStore)))
	mux.Handle("DELETE /admin/submissions/{id}", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, portal.AdminDeleteSubmissionHandler(d.SubmissionLog, d.Store, d.ScoresStore)))
	mux.Handle("/admin/summary", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, portal.AdminSummaryHandler(d.SubmissionLog, d.ExerciseStore, d.ScoresStore)))
	mux.Handle("/", assets.handler())
	return mux
}

// staticAssets serves the embedded frontend with a content-derived ETag and
// Cache-Control: no-cache.
//
// http.FileServer alone serves them with no validator whatsoever: go:embed
// gives every file a zero ModTime, so http.ServeContent omits Last-Modified,
// and it never generates an ETag of its own. A response carrying neither a
// validator nor a freshness directive leaves a browser free to keep using its
// cached copy without ever asking — which is how a deployed change to
// portal.js stayed invisible to a validator who had visited before. That was
// observed in practice, not theorised.
//
// "no-cache" means "revalidate before reusing", not "do not store": with the
// ETag in hand, a revalidation that finds nothing changed is a 304 with no
// body, so always asking costs one small round trip rather than the asset.
type staticAssets struct {
	fsys  fs.FS
	etags map[string]string
}

// newStaticAssets hashes every file once, at construction: the embedded
// contents cannot change while the process runs, so there is nothing to
// recompute per request.
func newStaticAssets(fsys fs.FS) *staticAssets {
	etags := make(map[string]string)

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		etags[path] = `"` + hex.EncodeToString(sum[:16]) + `"`
		return nil
	})
	if err != nil {
		// Not fatal: the assets still serve, they just revalidate the way
		// they did before this existed. Failing to start over a hashing
		// problem would be a worse trade than serving a stale-able page.
		log.Printf("static assets: unable to compute cache validators, falling back to unvalidated responses: %v", err)
	}

	return &staticAssets{fsys: fsys, etags: etags}
}

func (s *staticAssets) handler() http.Handler {
	files := http.FileServer(http.FS(s.fsys))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" || name == "." {
			name = "index.html"
		}
		s.setValidators(w, name)
		files.ServeHTTP(w, r)
	})
}

// serveFile is for the routes that serve one named asset directly rather
// than through the file server — /admin, whose page a browser cannot request
// with an Authorization header and so cannot go through the gated routes.
func (s *staticAssets) serveFile(w http.ResponseWriter, r *http.Request, name string) {
	s.setValidators(w, name)
	http.ServeFileFS(w, r, s.fsys, name)
}

// setValidators is a no-op for a name with no precomputed digest, so an
// unknown path still 404s through the file server rather than being handed
// a validator for content that does not exist.
func (s *staticAssets) setValidators(w http.ResponseWriter, name string) {
	etag, ok := s.etags[name]
	if !ok {
		return
	}
	// Set before delegating: http.ServeContent reads the ETag back out of
	// the header map to answer If-None-Match itself.
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
}

// submitHandlerFor builds the upload handler newMux serves at /submit.
// Extracted so the wiring can be asserted directly, without unpicking the
// routing table to reach the handler.
func submitHandlerFor(d muxDeps) *portal.SubmitHandler {
	return &portal.SubmitHandler{
		Sessions:      d.Sessions,
		Store:         d.Store,
		Log:           d.SubmissionLog,
		AVScanner:     d.AVScanner,
		Progress:      d.ProgressTracker,
		AVScanBudget:  d.AVScanBudget,
		Exercise:      d.ExerciseStore,
		Scores:        d.ScoresStore,
		MaxUploadSize: d.MaxUploadSize,

		ArchiveOptions: d.ArchiveOptions,
	}
}

func configureStore(uploadDir, s3Bucket, s3Region, s3Endpoint string) (storage.Store, error) {
	switch {
	case s3Bucket != "":
		return storage.NewS3Store(context.Background(), storage.S3Config{
			Bucket:    s3Bucket,
			Region:    s3Region,
			Endpoint:  s3Endpoint,
			AccessKey: os.Getenv("S3_ACCESS_KEY"),
			SecretKey: os.Getenv("S3_SECRET_KEY"),
		})
	case uploadDir != "":
		if err := os.MkdirAll(uploadDir, 0o755); err != nil {
			return nil, err
		}
		return storage.LocalStore{Dir: uploadDir}, nil
	default:
		return nil, errNoStorageBackend
	}
}

var errNoStorageBackend = errUsage("either -upload-dir or -s3-bucket is required")

type errUsage string

func (e errUsage) Error() string { return string(e) }

// configureAVScanner selects the antivirus scanner uploads are checked
// against, the same flags-in-decision-out shape as configureStore.
//
// Deliberately returns nil when addr is empty, rather than
// clamav.NoopScanner: a no-op scanner returns a clean verdict over every
// window, which would have the portal record complete coverage and the
// dashboard show a reassuring "scan ✓" on a submission no antivirus ever
// looked at. Nil records no coverage claim at all, which is the only
// honest answer. NoopScanner remains in the clamav package for tests,
// where claiming coverage is exactly what is wanted.
func configureAVScanner(addr string, timeout time.Duration) clamav.Scanner {
	if addr == "" {
		log.Println("-clamav-addr not set: uploads will NOT be scanned for malware (fine for local dev, not for production)")
		return nil
	}
	return clamav.ClamdScanner{Addr: addr, Timeout: timeout}
}

// loadOrGenerateSecret loads a hex-encoded HMAC secret from envVar, or
// generates a random 32-byte one for this run if envVar is unset —
// sessions issued with a generated secret won't survive a restart,
// which is fine for a single exercise but not a long-lived deployment.
func loadOrGenerateSecret(envVar string) ([]byte, error) {
	if hexSecret := os.Getenv(envVar); hexSecret != "" {
		return hex.DecodeString(hexSecret)
	}

	log.Printf("%s not set: generating a random one for this run (sessions won't survive a restart)", envVar)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// parseAdminAllowlist parses a comma-separated list of bech32 operator
// addresses into an allowlist set keyed by crypto.Address.String(). An
// empty list or any invalid address is an error — an admin surface with
// no valid credentials configured is a misconfiguration, not a
// degraded-but-running state.
func parseAdminAllowlist(csv string) (map[string]bool, error) {
	allowlist := map[string]bool{}
	for _, raw := range strings.Split(csv, ",") {
		addrStr := strings.TrimSpace(raw)
		if addrStr == "" {
			continue
		}
		addr, err := crypto.AddressFromBech32(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid admin operator address %q: %w", addrStr, err)
		}
		allowlist[addr.String()] = true
	}
	if len(allowlist) == 0 {
		return nil, errors.New("no admin operator addresses configured (ADMIN_OPERATOR_ADDRESSES is required)")
	}
	return allowlist, nil
}
