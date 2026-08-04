// Command portal is the validator fire drill submission portal: the
// challenge-tx auth endpoints, the archive upload endpoint, the admin
// submissions dashboard, and the static frontend, all in one binary.
//
// Storage backend: pass either -upload-dir (local disk, for testing) or
// -s3-bucket (+ -s3-region/-s3-endpoint, with credentials from the
// S3_ACCESS_KEY/S3_SECRET_KEY environment variables) for production.
//
// Required environment variables:
//   - ADMIN_PASSWORD — protects /admin and /admin/submissions.
//   - SESSION_SECRET (optional) — hex-encoded HMAC secret for session
//     tokens. If unset, a random one is generated for this run (sessions
//     won't survive a restart — fine for a single exercise, not for a
//     long-lived deployment).
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

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
// box). The bundled clamd.conf raises that limit to this same 2 GiB, so
// the two bounds agree; raising one without the other turns oversized
// uploads into 503s instead of a clean rejection.
const defaultMaxUploadSize = 2 << 30 // 2 GiB

// defaultMaxLogSize caps the gnoland.log.gz entry inside the archive.
// submission's own default is 2 GiB, which was harmless while those
// bytes were freed as soon as ValidateArchive returned — but Phase 3
// keeps them alive through the AV scan and the upload to storage, so
// they now cost up to that much resident memory per concurrent request.
// 64 MiB of gzip is on the order of a gigabyte of plaintext log, far
// more than the 8 MiB scoring.scanLogWindow will ever decompress, while
// keeping per-request retention bounded. Raise it with -max-log-size if
// real submissions ever bump into it (they are rejected with a clear
// message when they do).
const defaultMaxLogSize = 64 << 20 // 64 MiB

func main() {
	remote := flag.String("remote", "", "gno.land RPC endpoint to verify operator pubkeys against, e.g. https://rpc.test13.testnets.gno.land:443")
	addr := flag.String("addr", "localhost:8080", "address to listen on")
	sessionTTL := flag.Duration("session-ttl", 5*time.Minute, "how long an issued session token stays valid")
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
	maxLogSize := flag.Int64("max-log-size", defaultMaxLogSize, "maximum accepted size in bytes of the gnoland.log.gz entry inside the archive; these bytes are held in memory for the whole request")
	flag.Parse()

	if *remote == "" {
		log.Fatal("-remote is required (see docs/resources/gnoland-networks.md in gnolang/gno for known endpoints)")
	}

	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		log.Fatal("ADMIN_PASSWORD environment variable is required")
	}

	store, err := configureStore(*uploadDir, *s3Bucket, *s3Region, *s3Endpoint)
	if err != nil {
		log.Fatalf("unable to configure storage: %v", err)
	}

	sessionSecret, err := loadOrGenerateSessionSecret()
	if err != nil {
		log.Fatalf("unable to prepare session secret: %v", err)
	}
	sessions := auth.NewSessionSigner(sessionSecret, *sessionTTL)

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

	mux := http.NewServeMux()
	mux.Handle("/auth/challenge", auth.ChallengeHandler(nonces))
	mux.Handle("/auth/verify", auth.VerifyHandler(verifier, sessions))
	mux.Handle("/submit", &portal.SubmitHandler{
		Sessions:      sessions,
		Store:         store,
		Log:           submissionLog,
		AVScanner:     avScanner,
		Exercise:      exerciseStore,
		Scores:        scoresStore,
		MaxUploadSize: *maxUploadSize,

		ArchiveOptions: submission.Options{MaxLogSize: *maxLogSize},
	})
	mux.Handle("/admin", portal.AdminAuth(adminPassword, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, staticFS, "admin.html")
	})))
	mux.Handle("/admin/submissions", portal.AdminAuth(adminPassword, portal.AdminSubmissionsHandler(submissionLog, scoresStore)))
	mux.Handle("/admin/exercise", portal.AdminAuth(adminPassword, exercise.ConfigHandler(exerciseStore)))
	mux.Handle("POST /admin/submissions/{id}/score", portal.AdminAuth(adminPassword, portal.AdminScoreHandler(submissionLog, exerciseStore, scoresStore)))
	mux.Handle("/admin/summary", portal.AdminAuth(adminPassword, portal.AdminSummaryHandler(submissionLog, exerciseStore, scoresStore)))
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	log.Printf("listening on %s, verifying operator pubkeys against %s", *addr, *remote)
	log.Fatal(http.ListenAndServe(*addr, mux))
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

func loadOrGenerateSessionSecret() ([]byte, error) {
	if hexSecret := os.Getenv("SESSION_SECRET"); hexSecret != "" {
		return hex.DecodeString(hexSecret)
	}

	log.Println("SESSION_SECRET not set: generating a random one for this run (sessions won't survive a restart)")
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}
