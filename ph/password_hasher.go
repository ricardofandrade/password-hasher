package ph

import (
	"crypto/sha512"
	"encoding/base64"
	"sync/atomic"
)

// passwordHasher is the minimal interface for hashing passwords.
type passwordHasher interface {
	hashPassword(password string) (string, int64)
}

// sha512PasswordHasher ensures that each password hashed is tied to a unique ID.
type sha512PasswordHasher struct {
	uniqueId int64
}

// newSHA512PasswordHasher creates a new hasher.
func newSHA512PasswordHasher() *sha512PasswordHasher {
	return &sha512PasswordHasher{}
}

// hashPassword actually hashes the given plain-text password using SHA512, returns its ID and a base64-encoded hash.
func (pwHasher *sha512PasswordHasher) hashPassword(password string) (string, int64) {
	id := atomic.AddInt64(&pwHasher.uniqueId, 1)
	hashed := sha512.Sum512([]byte(password))
	encoded := base64.StdEncoding.EncodeToString(hashed[:])
	return encoded, id
}
