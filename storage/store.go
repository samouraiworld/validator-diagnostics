// Package storage persists validated submission archives to an object
// store. It only defines the Store interface and one concrete backend
// (S3-compatible object storage), per prd.md's decision to go with
// Object Storage first — SFTP, if ever needed, would be a second
// implementation of the same interface, not a rewrite of callers.
package storage

import (
	"context"
	"io"
)

// Store persists a submission archive under key. Implementations must
// treat body as untrusted bytes (see prd.md "Security Considerations")
// — Store itself does no archive validation; callers are expected to
// validate before calling Save.
type Store interface {
	Save(ctx context.Context, key string, body io.Reader, size int64) error
	// Delete removes the object at key. Deleting a key that doesn't
	// exist is not an error — callers may retry a delete that partially
	// succeeded.
	Delete(ctx context.Context, key string) error
}
