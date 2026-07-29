package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/gnolang/gno/tm2/pkg/crypto/keys"
)

// TestChallengeAndVerifyHandlers drives the two HTTP endpoints
// end-to-end, standing in for the network-dependent pubkey lookup with
// FetchPubKey so the test doesn't need a live chain — everything else
// (nonce issuance, tx/memo construction, real signing, real
// verification, single-use nonce enforcement) is exercised for real.
func TestChallengeAndVerifyHandlers(t *testing.T) {
	kb := keys.NewInMemory()
	info, err := kb.CreateAccount("operator", testMnemonic, "", "password", 0, 0)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	operatorAddr := info.GetAddress()

	store := NewNonceStore()
	verifier := &Verifier{
		Nonces: store,
		FetchPubKey: func(ctx context.Context, addr crypto.Address) (crypto.PubKey, error) {
			if addr != operatorAddr {
				t.Fatalf("unexpected address looked up: %s", addr)
			}
			return info.GetPubKey(), nil
		},
	}

	sessions := NewSessionSigner([]byte("test-secret"), 5*time.Minute)

	mux := http.NewServeMux()
	mux.Handle("/auth/challenge", ChallengeHandler(store))
	mux.Handle("/auth/verify", VerifyHandler(verifier, sessions))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1. Request a challenge.
	challengeReq, _ := json.Marshal(challengeRequest{OperatorAddress: operatorAddr.String()})
	resp, err := http.Post(srv.URL+"/auth/challenge", "application/json", bytes.NewReader(challengeReq))
	if err != nil {
		t.Fatalf("POST /auth/challenge: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge status = %d, want 200", resp.StatusCode)
	}

	var challenge challengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}
	if challenge.Nonce == "" {
		t.Fatal("expected non-empty nonce")
	}

	// 2. Sign it exactly as `gnokey sign` would (same tx/memo
	// construction the handler used, same Keybase.Sign primitive).
	tx := NewChallengeTx(operatorAddr, challenge.Nonce)
	signBytes, err := SignBytes(tx)
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	sig, _, err := kb.Sign("operator", "password", signBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// 3. Submit the signature.
	verifyReq, _ := json.Marshal(verifyRequest{
		OperatorAddress: operatorAddr.String(),
		Nonce:           challenge.Nonce,
		Signature:       base64.StdEncoding.EncodeToString(sig),
	})
	resp2, err := http.Post(srv.URL+"/auth/verify", "application/json", bytes.NewReader(verifyReq))
	if err != nil {
		t.Fatalf("POST /auth/verify: %v", err)
	}
	defer resp2.Body.Close()

	var result verifyResponse
	if err := json.NewDecoder(resp2.Body).Decode(&result); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if resp2.StatusCode != http.StatusOK || !result.OK {
		t.Fatalf("verify failed: status=%d ok=%v err=%q", resp2.StatusCode, result.OK, result.Error)
	}
	if result.SessionToken == "" {
		t.Fatal("expected a non-empty session_token on successful verify")
	}

	// The issued session token must authenticate as the same operator,
	// via the same RequireSession helper the (future) upload handler
	// will use.
	uploadReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/upload", nil)
	uploadReq.Header.Set("Authorization", "Bearer "+result.SessionToken)
	sessionAddr, err := RequireSession(sessions, uploadReq)
	if err != nil {
		t.Fatalf("RequireSession: unexpected error: %v", err)
	}
	if sessionAddr != operatorAddr {
		t.Fatalf("RequireSession returned %s, want %s", sessionAddr, operatorAddr)
	}

	// A request with no Authorization header must be rejected.
	bareReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/upload", nil)
	if _, err := RequireSession(sessions, bareReq); err != ErrInvalidSession {
		t.Fatalf("RequireSession(no header) error = %v, want ErrInvalidSession", err)
	}

	// 4. Replaying the same (now-burned) nonce/signature must fail.
	resp3, err := http.Post(srv.URL+"/auth/verify", "application/json", bytes.NewReader(verifyReq))
	if err != nil {
		t.Fatalf("POST /auth/verify (replay): %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", resp3.StatusCode)
	}
}
