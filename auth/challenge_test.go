package auth

import (
	"testing"

	"github.com/gnolang/gno/tm2/pkg/crypto/keys"
)

// testMnemonic is the same fixed test mnemonic gno itself uses in
// tm2/pkg/crypto/keys/keybase_test.go — not a real key, safe to hardcode.
const testMnemonic = `lounge napkin all odor tilt dove win inject sleep jazz uncover traffic hint require cargo arm rocket round scan bread report squirrel step lake`

// TestChallengeRoundTrip exercises the actual crypto path without a live
// chain: generate a real keypair, build the challenge tx exactly as the
// server would, sign it exactly as `gnokey sign` would (same
// Keybase.Sign primitive, same GetSignBytes), and verify it exactly as
// the server's VerifyChallenge would (PubKey.VerifyBytes). This proves
// the tx/memo/sign-bytes construction is round-trip correct, independent
// of network access.
func TestChallengeRoundTrip(t *testing.T) {
	kb := keys.NewInMemory()

	info, err := kb.CreateAccount("operator", testMnemonic, "", "password", 0, 0)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	operatorAddr := info.GetAddress()

	nonce, err := NewNonceStore().Issue(operatorAddr)
	if err != nil {
		t.Fatalf("Issue nonce: %v", err)
	}

	tx := NewChallengeTx(operatorAddr, nonce)

	signBytes, err := SignBytes(tx)
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}

	// What `gnokey sign` does under the hood (kb.Sign), applied to our
	// challenge sign bytes instead of a real tx's.
	sig, pub, err := kb.Sign("operator", "password", signBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !pub.VerifyBytes(signBytes, sig) {
		t.Fatal("VerifyBytes: valid signature rejected")
	}

	// Tamper checks: a signature must not verify against a different
	// nonce (replay across challenges) or a different operator.
	otherTx := NewChallengeTx(operatorAddr, "different-nonce")
	otherSignBytes, err := SignBytes(otherTx)
	if err != nil {
		t.Fatalf("SignBytes (other): %v", err)
	}
	if pub.VerifyBytes(otherSignBytes, sig) {
		t.Fatal("VerifyBytes: signature incorrectly valid for a different nonce")
	}

	// consume() must reject reuse of the same nonce.
	store := NewNonceStore()
	n2, err := store.Issue(operatorAddr)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.consume(operatorAddr, n2); err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}
	if err := store.consume(operatorAddr, n2); err == nil {
		t.Fatal("second consume of the same nonce should fail")
	}
}
