// Package auth implements the challenge-tx operator-key authentication
// protocol described in prd.md ("Authentication for the submission
// pipeline"). Validators prove control of their `valopers` OperatorAddress
// by signing a server-issued, never-broadcast challenge transaction with
// `gnokey sign`; the server verifies the signature against the operator's
// on-chain public key.
//
// This is a design skeleton: it builds and vets clean against
// github.com/gnolang/gno (go build ./... / go vet ./...), but it has not
// been exercised end-to-end against a real chain. It reuses primitives
// that already exist and are tested in gnolang/gno (tm2/pkg/crypto,
// tm2/pkg/std, tm2/pkg/sdk/bank, tm2/pkg/bft/rpc/client) rather than
// reimplementing signing/verification logic. Before wiring this into the
// portal: write tests, wire it to HTTP handlers, and test it end-to-end
// against a real gnokey-signed challenge on a live node/testnet.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gnolang/gno/tm2/pkg/amino"
	rpcclient "github.com/gnolang/gno/tm2/pkg/bft/rpc/client"
	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/gnolang/gno/tm2/pkg/sdk/bank"
	"github.com/gnolang/gno/tm2/pkg/std"
)

const (
	// MemoPrefix namespaces the nonce inside Tx.Memo so a signature can
	// never be confused with an unrelated, real transaction's memo.
	MemoPrefix = "validator-fire-drill-auth:v1:"

	// Sentinel signing parameters used only to compute GetSignBytes().
	// They deliberately do NOT match any real account's chain ID or
	// account number/sequence, so a leaked signature can never be
	// replayed as a valid on-chain transaction.
	SentinelChainID         = "fire-drill-auth-only"
	SentinelAccountNumber   = uint64(0)
	SentinelAccountSequence = uint64(0)

	// NonceTTL bounds how long an issued challenge stays valid.
	NonceTTL = 5 * time.Minute
)

// NewChallengeTx builds the unsigned challenge transaction for
// operatorAddr carrying nonce. The tx is a 1ugnot self-send and is never
// broadcast — the positive amount only exists so std.Tx/MsgSend's
// ValidateBasic() would accept it if something happened to call it; the
// operator is never actually charged since the tx never reaches the
// chain.
func NewChallengeTx(operatorAddr crypto.Address, nonce string) std.Tx {
	msg := bank.NewMsgSend(operatorAddr, operatorAddr, std.NewCoins(std.NewCoin("ugnot", 1)))

	return std.NewTx(
		[]std.Msg{msg},
		std.NewFee(1, std.NewCoin("ugnot", 0)),
		nil,
		MemoPrefix+nonce,
	)
}

// SignBytes returns the exact bytes the operator's `gnokey sign` call
// must produce a signature over, using the fixed sentinel signing
// parameters (see gnokey's --chainid/--account-number/--account-sequence
// flags in tm2/pkg/crypto/keys/client/sign.go).
func SignBytes(tx std.Tx) ([]byte, error) {
	return tx.GetSignBytes(SentinelChainID, SentinelAccountNumber, SentinelAccountSequence)
}

// --- Nonce issuance (single-use, TTL-bound) --------------------------------

type nonceEntry struct {
	operatorAddr crypto.Address
	expiresAt    time.Time
}

// NonceStore is a minimal in-memory single-use nonce tracker.
//
// TODO before production use: back this with a persistent/shared store
// (so it survives restarts and works across multiple portal instances)
// and add periodic cleanup of expired entries.
type NonceStore struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
}

func NewNonceStore() *NonceStore {
	return &NonceStore{entries: make(map[string]nonceEntry)}
}

// Issue generates a new random nonce bound to operatorAddr.
func (s *NonceStore) Issue(operatorAddr crypto.Address) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("unable to generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[nonce] = nonceEntry{
		operatorAddr: operatorAddr,
		expiresAt:    time.Now().Add(NonceTTL),
	}

	return nonce, nil
}

// consume validates and burns a nonce for operatorAddr. The nonce is
// removed regardless of outcome, so a given nonce can only ever be
// checked once — a failed check does not give a second attempt.
func (s *NonceStore) consume(operatorAddr crypto.Address, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[nonce]
	if !ok {
		return fmt.Errorf("unknown or already-used nonce")
	}
	delete(s.entries, nonce)

	if time.Now().After(entry.expiresAt) {
		return fmt.Errorf("nonce expired")
	}
	if entry.operatorAddr != operatorAddr {
		return fmt.Errorf("nonce was not issued for this operator address")
	}

	return nil
}

// --- Verification -----------------------------------------------------------

// Verifier checks challenge signatures against on-chain operator pubkeys.
type Verifier struct {
	Remote string // gno.land RPC endpoint, e.g. "https://rpc.gno.land:443"
	Nonces *NonceStore

	// FetchPubKey overrides how an operator's pubkey is resolved.
	// Defaults to querying Remote (via fetchOperatorPubKey). Exposed so
	// tests can supply a pubkey without needing a live chain.
	FetchPubKey func(ctx context.Context, addr crypto.Address) (crypto.PubKey, error)
}

// VerifyChallenge validates that sig is a valid signature by operatorAddr
// over the challenge tx identified by nonce. On success, the nonce is
// burned and the caller may consider operatorAddr authenticated for this
// submission.
func (v *Verifier) VerifyChallenge(ctx context.Context, operatorAddr crypto.Address, nonce string, sig []byte) error {
	if err := v.Nonces.consume(operatorAddr, nonce); err != nil {
		return fmt.Errorf("nonce check failed: %w", err)
	}

	tx := NewChallengeTx(operatorAddr, nonce)
	signBytes, err := SignBytes(tx)
	if err != nil {
		return fmt.Errorf("unable to compute sign bytes: %w", err)
	}

	lookup := v.FetchPubKey
	if lookup == nil {
		lookup = func(ctx context.Context, addr crypto.Address) (crypto.PubKey, error) {
			return fetchOperatorPubKey(ctx, v.Remote, addr)
		}
	}

	pubKey, err := lookup(ctx, operatorAddr)
	if err != nil {
		return fmt.Errorf("unable to fetch operator pubkey: %w", err)
	}

	if !pubKey.VerifyBytes(signBytes, sig) {
		return fmt.Errorf("invalid signature for operator address %s", operatorAddr)
	}

	return nil
}

// fetchOperatorPubKey queries the chain for operatorAddr's registered
// public key. Mirrors fetchAccount() in
// tm2/pkg/crypto/keys/client/verify.go — reusing the same ABCI query
// convention ("auth/accounts/<addr>") that gnokey itself relies on,
// rather than inventing a new lookup path.
func fetchOperatorPubKey(ctx context.Context, remote string, addr crypto.Address) (crypto.PubKey, error) {
	if remote == "" {
		return nil, fmt.Errorf("missing remote RPC endpoint")
	}

	cli, err := rpcclient.NewHTTPClient(remote)
	if err != nil {
		return nil, fmt.Errorf("unable to create RPC client: %w", err)
	}

	qres, err := cli.ABCIQuery(ctx, fmt.Sprintf("auth/accounts/%s", addr), []byte{})
	if err != nil {
		return nil, fmt.Errorf("unable to query account: %w", err)
	}

	if len(qres.Response.Data) == 0 || string(qres.Response.Data) == "null" {
		return nil, fmt.Errorf("account is not initialized on-chain: %s", addr)
	}

	// Mirrors fetchAccount()'s response struct in
	// tm2/pkg/crypto/keys/client/verify.go exactly: amino's JSON
	// unmarshaling rejects unknown fields, and the real response
	// includes "attributes" (the GnoAccount extension) alongside
	// "BaseAccount" — confirmed against a live query on topaz-1.
	var qret struct {
		BaseAccount std.BaseAccount
		Attributes  uint64 `json:"attributes"`
	}
	if err := amino.UnmarshalJSON(qres.Response.Data, &qret); err != nil {
		return nil, fmt.Errorf("unable to unmarshal account: %w", err)
	}

	if qret.BaseAccount.PubKey == nil {
		return nil, fmt.Errorf("operator address %s has no public key on-chain yet", addr)
	}

	return qret.BaseAccount.PubKey, nil
}

// MarshalChallengeTx renders the unsigned challenge tx as the Amino JSON
// document served to the validator for `gnokey sign --tx-path`.
func MarshalChallengeTx(tx std.Tx) ([]byte, error) {
	bz, err := amino.MarshalJSON(tx)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal challenge tx: %w", err)
	}
	// Re-indent for a friendlier downloadable file; not required for
	// gnokey to accept it.
	var pretty json.RawMessage = bz
	return json.MarshalIndent(pretty, "", "  ")
}
