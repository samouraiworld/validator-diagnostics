package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gnolang/gno/tm2/pkg/crypto"
)

// This file wires the challenge-tx protocol to two HTTP endpoints, plus
// the session-token bridge to whatever endpoint accepts the archive
// upload next (see session.go): a successful /auth/verify mints a
// short-lived SessionSigner token binding the operator address, which
// the upload endpoint verifies via RequireSession.

type challengeRequest struct {
	OperatorAddress string `json:"operator_address"`
}

type challengeResponse struct {
	Nonce           string          `json:"nonce"`
	ChallengeTx     json.RawMessage `json:"challenge_tx"`
	ChainID         string          `json:"chainid"`
	AccountNumber   uint64          `json:"account_number"`
	AccountSequence uint64          `json:"account_sequence"`
}

// ChallengeHandler issues a new nonce and unsigned challenge tx for the
// operator address supplied in the request body.
//
//	POST /auth/challenge
//	{"operator_address": "g1..."}
func ChallengeHandler(store *NonceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req challengeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		operatorAddr, err := crypto.AddressFromBech32(req.OperatorAddress)
		if err != nil {
			http.Error(w, "invalid operator_address", http.StatusBadRequest)
			return
		}

		nonce, err := store.Issue(operatorAddr)
		if err != nil {
			http.Error(w, "unable to issue challenge", http.StatusInternalServerError)
			return
		}

		txJSON, err := MarshalChallengeTx(NewChallengeTx(operatorAddr, nonce))
		if err != nil {
			http.Error(w, "unable to build challenge", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, challengeResponse{
			Nonce:           nonce,
			ChallengeTx:     txJSON,
			ChainID:         SentinelChainID,
			AccountNumber:   SentinelAccountNumber,
			AccountSequence: SentinelAccountSequence,
		})
	}
}

type verifyRequest struct {
	OperatorAddress string `json:"operator_address"`
	Nonce           string `json:"nonce"`
	Signature       string `json:"signature"` // base64, as produced by `gnokey sign`'s signature document
}

type verifyResponse struct {
	OK           bool   `json:"ok"`
	SessionToken string `json:"session_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

// VerifyHandler checks a signed challenge and, on success, mints a
// session token for the operator address via sessions.
//
//	POST /auth/verify
//	{"operator_address": "g1...", "nonce": "...", "signature": "<base64>"}
func VerifyHandler(v *Verifier, sessions *SessionSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req verifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "invalid request body"})
			return
		}

		operatorAddr, err := crypto.AddressFromBech32(req.OperatorAddress)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "invalid operator_address"})
			return
		}

		sig, err := base64.StdEncoding.DecodeString(req.Signature)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "invalid signature encoding"})
			return
		}

		if err := v.VerifyChallenge(r.Context(), operatorAddr, req.Nonce, sig); err != nil {
			writeJSON(w, http.StatusUnauthorized, verifyResponse{Error: err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, verifyResponse{
			OK:           true,
			SessionToken: sessions.Issue(operatorAddr),
		})
	}
}

// RequireSession extracts and verifies the session token from the
// "Authorization: Bearer <token>" header, returning the bound operator
// address. Intended for the (not-yet-built) archive-upload handler:
//
//	operatorAddr, err := auth.RequireSession(sessions, r)
//	if err != nil {
//	    http.Error(w, "unauthorized", http.StatusUnauthorized)
//	    return
//	}
func RequireSession(sessions *SessionSigner, r *http.Request) (crypto.Address, error) {
	const prefix = "Bearer "

	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return crypto.Address{}, ErrInvalidSession
	}

	return sessions.Verify(strings.TrimPrefix(h, prefix))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
