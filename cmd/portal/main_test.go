package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/gnolang/gno/tm2/pkg/crypto/keys"
	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/clamav"
	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
	"github.com/samourai/validator-diagnostics/submission"
)

// TestDeleteSubmissionRouteRequiresAdminAuth guards the one line in
// main() that stands between the internet and a destructive endpoint —
// a refactor that dropped the RequireAdminSession wrapper would
// otherwise go unnoticed, since AdminDeleteSubmissionHandler itself has
// no auth of its own by design (auth is applied once, at the wiring
// layer, for every /admin/* route).
func TestDeleteSubmissionRouteRequiresAdminAuth(t *testing.T) {
	log := portal.NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	store := storage.LocalStore{Dir: t.TempDir()}
	scores := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

	sessions := auth.NewSessionSigner([]byte("test-secret"), time.Hour)
	allowlist := map[string]bool{"g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f": true}

	mux := http.NewServeMux()
	mux.Handle("DELETE /admin/submissions/{id}", portal.RequireAdminSession(sessions, allowlist, portal.AdminDeleteSubmissionHandler(log, store, scores)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/admin/submissions/some-id", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Deliberately no Authorization header set.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (unauthenticated request must be rejected)", resp.StatusCode)
	}
}

// TestNewMux_AdminLoginRoundTrip exercises the real routing table built
// by newMux — the same one main() serves — end to end: an admin signs
// in via the actual /auth/challenge + /auth/admin/verify endpoints with
// a real signature, and the resulting token must authenticate against a
// real /admin/* route. It also asserts /admin itself is reachable with
// no session (it's the sign-in page), and that a validator-flow session
// token (issued by the *other* SessionSigner) must NOT authenticate
// against admin routes — the whole point of keeping the two signers
// separate.
func TestNewMux_AdminLoginRoundTrip(t *testing.T) {
	// Same fixed, publicly-known test mnemonic gno itself uses in
	// tm2/pkg/crypto/keys/keybase_test.go (see also auth/challenge_test.go) —
	// not a real key.
	const testMnemonic = `lounge napkin all odor tilt dove win inject sleep jazz uncover traffic hint require cargo arm rocket round scan bread report squirrel step lake`

	kb := keys.NewInMemory()
	info, err := kb.CreateAccount("admin-operator", testMnemonic, "", "password", 0, 0)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	operatorAddr := info.GetAddress()

	nonces := auth.NewNonceStore()
	verifier := &auth.Verifier{
		Nonces: nonces,
		FetchPubKey: func(ctx context.Context, addr crypto.Address) (crypto.PubKey, error) {
			return info.GetPubKey(), nil
		},
	}

	sessions := auth.NewSessionSigner([]byte("test-validator-secret"), 5*time.Minute)
	adminSessions := auth.NewSessionSigner([]byte("test-admin-secret"), time.Hour)
	allowlist := map[string]bool{operatorAddr.String(): true}

	fileLog := portal.NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	store := storage.LocalStore{Dir: t.TempDir()}

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}

	mux := newMux(muxDeps{
		Verifier:       verifier,
		Nonces:         nonces,
		Sessions:       sessions,
		AdminSessions:  adminSessions,
		AdminAllowlist: allowlist,
		Store:          store,
		SubmissionLog:  fileLog,
		ExerciseStore:  exerciseStore,
		ScoresStore:    scoresStore,
		AVScanner:      clamav.NoopScanner{},
		MaxUploadSize:  defaultMaxUploadSize,
		ArchiveOptions: submission.Options{MaxLogSize: defaultMaxLogSize},
		StaticFS:       staticFS,
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// GET /admin must be reachable with no session at all (it's the
	// login page itself — the regression this test exists to catch).
	resp, err := http.Get(srv.URL + "/admin")
	if err != nil {
		t.Fatalf("GET /admin: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin status = %d, want 200 (the admin login page must be reachable without a session)", resp.StatusCode)
	}

	// 1. Get a challenge.
	challengeReq, _ := json.Marshal(map[string]string{"operator_address": operatorAddr.String()})
	resp, err = http.Post(srv.URL+"/auth/challenge", "application/json", bytes.NewReader(challengeReq))
	if err != nil {
		t.Fatalf("POST /auth/challenge: %v", err)
	}
	defer resp.Body.Close()
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if challenge.Nonce == "" {
		t.Fatal("expected non-empty nonce")
	}

	// 2. Sign it exactly as gnokey sign would.
	tx := auth.NewChallengeTx(operatorAddr, challenge.Nonce)
	signBytes, err := auth.SignBytes(tx)
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	sig, _, err := kb.Sign("admin-operator", "password", signBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// 3. Verify against the ADMIN endpoint specifically — this is the
	// regression this test exists to catch: an admin session token must
	// come from /auth/admin/verify (signed with adminSessions), not the
	// validator flow's /auth/verify (signed with sessions).
	verifyReq, _ := json.Marshal(map[string]string{
		"operator_address": operatorAddr.String(),
		"nonce":            challenge.Nonce,
		"signature":        base64.StdEncoding.EncodeToString(sig),
	})
	resp, err = http.Post(srv.URL+"/auth/admin/verify", "application/json", bytes.NewReader(verifyReq))
	if err != nil {
		t.Fatalf("POST /auth/admin/verify: %v", err)
	}
	defer resp.Body.Close()
	var verifyResp struct {
		OK           bool   `json:"ok"`
		SessionToken string `json:"session_token"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !verifyResp.OK {
		t.Fatalf("admin verify failed: status=%d ok=%v err=%q", resp.StatusCode, verifyResp.OK, verifyResp.Error)
	}

	// 4. The returned token must actually authenticate against a real
	// admin route.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/submissions", nil)
	req.Header.Set("Authorization", "Bearer "+verifyResp.SessionToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/submissions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/submissions with admin token: status = %d, want 200", resp.StatusCode)
	}

	// 5. The validator upload session signer must NOT authenticate
	// against admin routes (secret separation must actually hold).
	otherToken := sessions.Issue(operatorAddr)
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/submissions", nil)
	req2.Header.Set("Authorization", "Bearer "+otherToken)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET /admin/submissions (validator token): %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /admin/submissions with a validator-flow token: status = %d, want 401 (validator and admin sessions must not cross-authenticate)", resp2.StatusCode)
	}
}

func TestParseAdminAllowlist(t *testing.T) {
	t.Run("valid list", func(t *testing.T) {
		allowlist, err := parseAdminAllowlist("g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f, g18yurwd34xsenyvfs8yurwd34xsenyvfsaffa87")
		if err != nil {
			t.Fatalf("parseAdminAllowlist: unexpected error: %v", err)
		}
		want := []string{
			"g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f",
			"g18yurwd34xsenyvfs8yurwd34xsenyvfsaffa87",
		}
		if len(allowlist) != len(want) {
			t.Fatalf("allowlist = %v, want %d entries", allowlist, len(want))
		}
		for _, addr := range want {
			if !allowlist[addr] {
				t.Errorf("allowlist missing %s", addr)
			}
		}
	})

	t.Run("invalid address", func(t *testing.T) {
		if _, err := parseAdminAllowlist("not-a-valid-address"); err == nil {
			t.Fatal("parseAdminAllowlist: want error for invalid address, got nil")
		}
	})

	t.Run("empty list", func(t *testing.T) {
		if _, err := parseAdminAllowlist(""); err == nil {
			t.Fatal("parseAdminAllowlist: want error for empty list, got nil")
		}
	})

	t.Run("blank entries are skipped, not treated as invalid", func(t *testing.T) {
		allowlist, err := parseAdminAllowlist("g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f,, ")
		if err != nil {
			t.Fatalf("parseAdminAllowlist: unexpected error: %v", err)
		}
		if len(allowlist) != 1 || !allowlist["g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f"] {
			t.Errorf("allowlist = %v, want exactly the one real address", allowlist)
		}
	})
}

func TestSubmitHandlerFor_PassesTheAVScanBudget(t *testing.T) {
	h := submitHandlerFor(muxDeps{
		AVScanner:    clamav.NoopScanner{},
		AVScanBudget: 4096,
	})
	if h.AVScanBudget != 4096 {
		t.Errorf("AVScanBudget = %d, want 4096", h.AVScanBudget)
	}
	if h.AVScanner == nil {
		t.Error("AVScanner = nil, want the wired scanner")
	}
}

func TestSubmitHandlerFor_NilScannerStaysNil(t *testing.T) {
	// Guards only the field wiring in submitHandlerFor: a nil d.AVScanner
	// must come out the other end still nil, not silently replaced.
	// configureAVScanner is what actually decides whether main() wires a
	// nil scanner in the first place — see
	// TestConfigureAVScanner_EmptyAddrReturnsNil for that guard.
	if h := submitHandlerFor(muxDeps{}); h.AVScanner != nil {
		t.Errorf("AVScanner = %#v, want nil when none was wired", h.AVScanner)
	}
}

func TestConfigureAVScanner_EmptyAddrReturnsNil(t *testing.T) {
	// This is the actual regression site for "no clamd address configured
	// must not silently become a working scanner": comparing the returned
	// clamav.Scanner to nil catches both a typed-nil *clamav.ClamdScanner
	// (which the == nil trap would miss if we asserted on a concrete
	// type instead) and a clamav.NoopScanner{} substituted back in by
	// mistake (which is a valid, non-nil Scanner value).
	if s := configureAVScanner("", time.Minute); s != nil {
		t.Errorf("configureAVScanner(\"\", ...) = %#v, want nil", s)
	}
}

func TestConfigureAVScanner_NonEmptyAddrReturnsClamdScanner(t *testing.T) {
	s := configureAVScanner("clamav:3310", 5*time.Minute)
	got, ok := s.(clamav.ClamdScanner)
	if !ok {
		t.Fatalf("configureAVScanner(...) = %#v (%T), want clamav.ClamdScanner", s, s)
	}
	if got.Addr != "clamav:3310" {
		t.Errorf("Addr = %q, want %q", got.Addr, "clamav:3310")
	}
	if got.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want %v", got.Timeout, 5*time.Minute)
	}
}

func TestSubmitHandlerFor_PassesTheProgressTracker(t *testing.T) {
	tracker := portal.NewProgressTracker()
	if h := submitHandlerFor(muxDeps{ProgressTracker: tracker}); h.Progress != tracker {
		t.Error("Progress did not reach the handler")
	}
}

func TestNewMux_RoutesSubmitProgress(t *testing.T) {
	// /submit is registered as an exact pattern, so /submit/progress does not
	// collide with it — but adding a trailing slash to either registration
	// would silently change which handler wins, so assert the routing.
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	tracker := portal.NewProgressTracker()

	mux := newMux(muxDeps{
		Sessions:        sessions,
		AdminSessions:   auth.NewSessionSigner([]byte("admin-secret"), 5*time.Minute),
		Store:           storage.LocalStore{Dir: t.TempDir()},
		SubmissionLog:   portal.NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl")),
		ExerciseStore:   exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json")),
		ScoresStore:     scoring.NewStore(filepath.Join(t.TempDir(), "scores.json")),
		ProgressTracker: tracker,
		StaticFS:        os.DirFS(t.TempDir()),
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	var addr crypto.Address
	copy(addr[:], []byte("01234567890123456789")) // 20 bytes

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/submit/progress", nil)
	req.Header.Set("Authorization", "Bearer "+sessions.Issue(addr))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /submit/progress: %v", err)
	}
	defer resp.Body.Close()

	// 404 from the progress handler, not 405 from /submit's POST-only guard:
	// the session is valid and nothing is in flight.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 from the progress handler", resp.StatusCode)
	}
}

// TestStaticAssets_AreRevalidatable pins the fix for a defect observed in
// production: a validator whose browser had visited before kept running an
// older portal.js after a deploy, so a shipped change was simply invisible
// to them.
//
// The cause is that go:embed gives every file a zero ModTime, so
// http.ServeContent omits Last-Modified, and http.FileServer generates no
// ETag of its own — leaving the response with no validator and no freshness
// directive at all, which lets a browser keep serving its cached copy
// without ever asking. fstest.MapFS reproduces that exactly: its files also
// have a zero ModTime.
func TestStaticAssets_AreRevalidatable(t *testing.T) {
	fsys := fstest.MapFS{
		"portal.js": &fstest.MapFile{Data: []byte("console.log('v1');\n")},
	}

	srv := httptest.NewServer(newStaticAssets(fsys).handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/portal.js")
	if err != nil {
		t.Fatalf("GET /portal.js: %v", err)
	}
	defer resp.Body.Close()

	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag: without a validator a browser has nothing to revalidate against")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want \"no-cache\" so the browser always asks before reusing", got)
	}

	// Revalidation must be cheap, or "always ask" would mean re-sending
	// every asset on every page load.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/portal.js", nil)
	req.Header.Set("If-None-Match", etag)
	cond, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("conditional GET: %v", err)
	}
	defer cond.Body.Close()
	if cond.StatusCode != http.StatusNotModified {
		t.Errorf("status = %d, want 304 for a matching If-None-Match", cond.StatusCode)
	}
}

func TestStaticAssets_ETagFollowsContent(t *testing.T) {
	// The property the whole fix rests on: change the bytes, change the
	// validator. An ETag that survived a deploy would be worse than none.
	v1 := newStaticAssets(fstest.MapFS{"portal.js": &fstest.MapFile{Data: []byte("console.log('v1');\n")}})
	v2 := newStaticAssets(fstest.MapFS{"portal.js": &fstest.MapFile{Data: []byte("console.log('v2');\n")}})

	if v1.etags["portal.js"] == "" {
		t.Fatal("no ETag computed for portal.js")
	}
	if v1.etags["portal.js"] == v2.etags["portal.js"] {
		t.Error("different content produced the same ETag: a deploy would stay invisible")
	}
}

func TestStaticAssets_ServeFileAlsoRevalidates(t *testing.T) {
	// /admin is served by its own route rather than through the file
	// server, so it needs the same treatment — a stale admin dashboard is
	// the same defect wearing a different hat.
	fsys := fstest.MapFS{
		"admin.html": &fstest.MapFile{Data: []byte("<h1>admin</h1>\n")},
	}
	assets := newStaticAssets(fsys)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assets.serveFile(w, r, "admin.html")
	}))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/admin")
	if err != nil {
		t.Fatalf("GET /admin: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("ETag") == "" {
		t.Error("no ETag on the admin page")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want \"no-cache\"", got)
	}
}
