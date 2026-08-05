// Command portal is the validator fire drill submission portal: the
// challenge-tx auth endpoints, the archive upload endpoint, the admin
// submissions dashboard, and the static frontend, all in one binary.
//
// Storage backend: pass either -upload-dir (local disk, for testing) or
// -s3-bucket (+ -s3-region/-s3-endpoint, with credentials from the
// S3_ACCESS_KEY/S3_SECRET_KEY environment variables) for production.
//
// Uploads are streamed to clamd for a malware scan before being stored
// when -clamav-addr is set; the scan fails closed, so keep
// -max-upload-size at or below clamd's own StreamMaxLength (the bundled
// clamd.conf sets both to 2 GiB) or real uploads are rejected with 503.
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
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
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
// 10 GB": every upload is streamed to clamd before it is stored, and
// clamd refuses anything past its own StreamMaxLength (25 MiB out of the
// box). The bundled clamd.conf raises that limit to this same value, so
// the two bounds agree; raising one without the other turns oversized
// uploads into 503s instead of a clean rejection.
//
// The value is 2 GiB minus one byte rather than a round 2 GiB because
// libclamav cannot scan a file of 2147483648 bytes or more at all — no
// clamd.conf setting lifts that, so an upload of exactly 2 GiB would be
// accepted here and then fail the scan with a 503. See clamd.conf's own
// comment for the warning clamd logs when you try.
const defaultMaxUploadSize = 2147483647 // 2 GiB - 1, libclamav's hard scan ceiling

// defaultMaxLogSize caps the gnoland.log.gz entry inside the archive.
// submission's own default is 2 GiB; this deployment standardises lower so
// one submission cannot tie up an unbounded amount of decompression work.
//
// The entry is streamed and never buffered (see submission.ValidateArchive
// and submission.OpenLog), so this bounds *compressed* bytes read out of
// the archive rather than resident memory. The separate bound on
// *decompressed* bytes is scoring.maxLogScanBytes (1 GiB), which is what
// stops a small upload from expanding without limit during the
// log-window scan.
//
// 256 MiB is roughly 2.5x the largest real submission seen so far. Raise it
// with -max-log-size (MAX_LOG_SIZE in .env) if real submissions bump into
// it — they are rejected with a clear message when they do. README.md's
// "Upload size and ClamAV" lists what else has to move with it.
const defaultMaxLogSize = 256 << 20 // 256 MiB

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
	clamavTimeout := flag.Duration("clamav-timeout", 15*time.Minute, "how long a single clamd scan may take, dial included; must comfortably cover streaming a whole -max-upload-size archive to clamd")
	maxUploadSize := flag.Int64("max-upload-size", defaultMaxUploadSize, "maximum accepted upload size in bytes; keep this <= clamd's StreamMaxLength (see clamd.conf) or scannable uploads will be rejected with 503")
	maxLogSize := flag.Int64("max-log-size", defaultMaxLogSize, "maximum accepted size in bytes of the gnoland.log.gz entry inside the archive; the entry is streamed rather than buffered, so this bounds decompression work rather than memory")
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

	var avScanner clamav.Scanner = clamav.NoopScanner{}
	if *clamavAddr != "" {
		avScanner = clamav.ClamdScanner{Addr: *clamavAddr, Timeout: *clamavTimeout}
	} else {
		log.Println("-clamav-addr not set: uploads will NOT be scanned for malware (fine for local dev, not for production)")
	}

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("unable to load embedded static assets: %v", err)
	}

	mux := newMux(muxDeps{
		Verifier:       verifier,
		Nonces:         nonces,
		Sessions:       sessions,
		AdminSessions:  adminSessions,
		AdminAllowlist: adminAllowlist,
		Store:          store,
		SubmissionLog:  submissionLog,
		ExerciseStore:  exerciseStore,
		ScoresStore:    scoresStore,
		AVScanner:      avScanner,
		MaxUploadSize:  *maxUploadSize,
		ArchiveOptions: submission.Options{MaxLogSize: *maxLogSize},
		StaticFS:       staticFS,
	})

	log.Printf("listening on %s, verifying operator pubkeys against %s", *addr, *remote)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// muxDeps groups every dependency newMux needs to wire the portal's
// routes. Extracted from main() so the routing table itself — not just
// individual middleware in isolation — can be exercised by a real HTTP
// round trip in tests.
type muxDeps struct {
	Verifier       *auth.Verifier
	Nonces         *auth.NonceStore
	Sessions       *auth.SessionSigner
	AdminSessions  *auth.SessionSigner
	AdminAllowlist map[string]bool
	Store          storage.Store
	SubmissionLog  *portal.FileLog
	ExerciseStore  *exercise.FileStore
	ScoresStore    *scoring.Store
	AVScanner      clamav.Scanner
	MaxUploadSize  int64
	ArchiveOptions submission.Options
	StaticFS       fs.FS
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
	mux := http.NewServeMux()
	mux.Handle("/auth/challenge", auth.ChallengeHandler(d.Nonces))
	mux.Handle("/auth/verify", auth.VerifyHandler(d.Verifier, d.Sessions))
	mux.Handle("/auth/admin/verify", auth.VerifyHandler(d.Verifier, d.AdminSessions))
	mux.Handle("/submit", &portal.SubmitHandler{
		Sessions:      d.Sessions,
		Store:         d.Store,
		Log:           d.SubmissionLog,
		AVScanner:     d.AVScanner,
		Exercise:      d.ExerciseStore,
		Scores:        d.ScoresStore,
		MaxUploadSize: d.MaxUploadSize,

		ArchiveOptions: d.ArchiveOptions,
	})
	mux.Handle("/admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, d.StaticFS, "admin.html")
	}))
	mux.Handle("/admin/submissions", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, portal.AdminSubmissionsHandler(d.SubmissionLog, d.ScoresStore)))
	mux.Handle("/admin/exercise", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, exercise.ConfigHandler(d.ExerciseStore)))
	mux.Handle("POST /admin/submissions/{id}/score", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, portal.AdminScoreHandler(d.SubmissionLog, d.ScoresStore)))
	mux.Handle("DELETE /admin/submissions/{id}", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, portal.AdminDeleteSubmissionHandler(d.SubmissionLog, d.Store, d.ScoresStore)))
	mux.Handle("/admin/summary", portal.RequireAdminSession(d.AdminSessions, d.AdminAllowlist, portal.AdminSummaryHandler(d.SubmissionLog, d.ExerciseStore, d.ScoresStore)))
	mux.Handle("/", http.FileServer(http.FS(d.StaticFS)))
	return mux
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
