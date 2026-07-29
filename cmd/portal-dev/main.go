// Command portal-dev runs a minimal local HTTP server exposing the
// full submission flow (challenge-tx auth + archive upload), for
// manually testing against a real gno.land network with a real operator
// key. This is a dev/test tool, not the production portal: no TLS, no
// rate limiting, no persistence beyond the in-memory nonce store
// (restarting the process invalidates any outstanding challenges), and
// archives are saved to a local directory rather than real object
// storage (see storage.S3Store for that, once real credentials exist).
package main

import (
	"crypto/rand"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/storage"
)

func main() {
	remote := flag.String("remote", "", "gno.land RPC endpoint to verify operator pubkeys against, e.g. https://rpc.test13.testnets.gno.land:443")
	addr := flag.String("addr", "localhost:8080", "address to listen on")
	sessionTTL := flag.Duration("session-ttl", 5*time.Minute, "how long an issued session token stays valid")
	uploadDir := flag.String("upload-dir", "./portal-dev-uploads", "local directory to save submitted archives into")
	flag.Parse()

	if *remote == "" {
		log.Fatal("-remote is required (see docs/resources/gnoland-networks.md in gnolang/gno for known endpoints)")
	}

	if err := os.MkdirAll(*uploadDir, 0o755); err != nil {
		log.Fatalf("unable to create -upload-dir %s: %v", *uploadDir, err)
	}

	// A random secret each run is fine for local testing: it just means
	// tokens (like nonces) don't survive a restart. A real deployment
	// must load a stable secret instead.
	sessionSecret := make([]byte, 32)
	if _, err := rand.Read(sessionSecret); err != nil {
		log.Fatalf("unable to generate session secret: %v", err)
	}
	sessions := auth.NewSessionSigner(sessionSecret, *sessionTTL)

	nonces := auth.NewNonceStore()
	verifier := &auth.Verifier{Remote: *remote, Nonces: nonces}
	archiveStore := storage.LocalStore{Dir: *uploadDir}

	mux := http.NewServeMux()
	mux.Handle("/auth/challenge", auth.ChallengeHandler(nonces))
	mux.Handle("/auth/verify", auth.VerifyHandler(verifier, sessions))
	mux.Handle("/submit", &portal.SubmitHandler{Sessions: sessions, Store: archiveStore})

	log.Printf("listening on %s, verifying operator pubkeys against %s, saving archives to %s", *addr, *remote, *uploadDir)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
