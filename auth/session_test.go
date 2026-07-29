package auth

import (
	"testing"
	"time"

	"github.com/gnolang/gno/tm2/pkg/crypto"
)

func TestSessionSigner_RoundTrip(t *testing.T) {
	signer := NewSessionSigner([]byte("test-secret"), 5*time.Minute)

	var addr crypto.Address
	copy(addr[:], []byte("01234567890123456789")) // 20 bytes

	token := signer.Issue(addr)

	got, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if got != addr {
		t.Errorf("Verify returned address %s, want %s", got, addr)
	}
}

func TestSessionSigner_RejectsTamperedToken(t *testing.T) {
	signer := NewSessionSigner([]byte("test-secret"), 5*time.Minute)

	var addr crypto.Address
	copy(addr[:], []byte("01234567890123456789"))

	token := signer.Issue(addr)
	tampered := []byte(token)
	// Flip a character in the middle of the base64 payload.
	if tampered[10] == 'a' {
		tampered[10] = 'b'
	} else {
		tampered[10] = 'a'
	}

	if _, err := signer.Verify(string(tampered)); err != ErrInvalidSession {
		t.Fatalf("Verify(tampered) error = %v, want ErrInvalidSession", err)
	}
}

func TestSessionSigner_RejectsWrongSecret(t *testing.T) {
	issuer := NewSessionSigner([]byte("secret-a"), 5*time.Minute)
	verifier := NewSessionSigner([]byte("secret-b"), 5*time.Minute)

	var addr crypto.Address
	copy(addr[:], []byte("01234567890123456789"))

	token := issuer.Issue(addr)

	if _, err := verifier.Verify(token); err != ErrInvalidSession {
		t.Fatalf("Verify with wrong secret error = %v, want ErrInvalidSession", err)
	}
}

func TestSessionSigner_RejectsExpiredToken(t *testing.T) {
	signer := NewSessionSigner([]byte("test-secret"), -1*time.Minute) // already expired

	var addr crypto.Address
	copy(addr[:], []byte("01234567890123456789"))

	token := signer.Issue(addr)

	if _, err := signer.Verify(token); err != ErrInvalidSession {
		t.Fatalf("Verify(expired) error = %v, want ErrInvalidSession", err)
	}
}

func TestSessionSigner_RejectsGarbageToken(t *testing.T) {
	signer := NewSessionSigner([]byte("test-secret"), 5*time.Minute)

	for _, tok := range []string{"", "not-base64!!!", "aGVsbG8"} {
		if _, err := signer.Verify(tok); err != ErrInvalidSession {
			t.Errorf("Verify(%q) error = %v, want ErrInvalidSession", tok, err)
		}
	}
}
