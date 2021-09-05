package ph

import (
	"crypto/sha512"
	"encoding/base64"
	"sync/atomic"
)

// passwordHasher ensures that each password hashed is tied to a unique ID.
type passwordHasher struct {
	uniqueId int64
}

// newPasswordHasher creates a new hasher.
func newPasswordHasher() *passwordHasher {
	return &passwordHasher{}
}

// hashPassword actually hashes the given plain-text password using SHA512, returns its ID and a base64-encoded hash.
func (pwHasher *passwordHasher) hashPassword(password string) (string, int64) {
	id := atomic.AddInt64(&pwHasher.uniqueId, 1)
	hashed := sha512.Sum512([]byte(password))
	encoded := base64.StdEncoding.EncodeToString(hashed[:])
	return encoded, id
}
