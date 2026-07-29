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
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/storage"
)

//go:embed static
var staticFiles embed.FS

func main() {
	remote := flag.String("remote", "", "gno.land RPC endpoint to verify operator pubkeys against, e.g. https://rpc.test13.testnets.gno.land:443")
	addr := flag.String("addr", "localhost:8080", "address to listen on")
	sessionTTL := flag.Duration("session-ttl", 5*time.Minute, "how long an issued session token stays valid")
	uploadDir := flag.String("upload-dir", "", "local directory to save submitted archives into (use this OR the -s3-* flags)")
	s3Bucket := flag.String("s3-bucket", "", "S3-compatible bucket to save submitted archives into")
	s3Region := flag.String("s3-region", "", "S3-compatible region")
	s3Endpoint := flag.String("s3-endpoint", "", "S3-compatible endpoint (leave empty for real AWS S3)")
	logPath := flag.String("log-path", "./submissions.jsonl", "path to the submission log file, read by the admin dashboard")
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

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("unable to load embedded static assets: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/challenge", auth.ChallengeHandler(nonces))
	mux.Handle("/auth/verify", auth.VerifyHandler(verifier, sessions))
	mux.Handle("/submit", &portal.SubmitHandler{Sessions: sessions, Store: store, Log: submissionLog})
	mux.Handle("/admin", portal.AdminAuth(adminPassword, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, staticFS, "admin.html")
	})))
	mux.Handle("/admin/submissions", portal.AdminAuth(adminPassword, portal.AdminSubmissionsHandler(submissionLog)))
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
