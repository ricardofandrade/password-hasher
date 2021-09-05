package ph

import (
	"log"
	"sync"
	"time"
)

// passwordHashStore is an in-memory delayed storage of hashed passwords.
// FIXME: There's currently no strategy to rotate or purge the password hashes.
//        Not only this is an issue due to the amount of memory used, but sequential IDs are easily guessable. The hash
//        even though "secure" (no known issues with SHA-512), length extension and table matching are still possible.
type passwordHashStore struct {
	hashes   map[int64]string
	hashLock sync.RWMutex
	wg       sync.WaitGroup
}

// newPasswordHashStore creates a new store.
func newPasswordHashStore() *passwordHashStore {
	return &passwordHashStore{
		hashes: make(map[int64]string),
	}
}

// delayStore actually stores the password hash tied to its id after a 5-second delay.
func (store *passwordHashStore) delayStore(hashed string, id int64) {
	log.Printf("Storing for %d ...", id)

	// mark storage as pending and impose delay
	store.wg.Add(1)
	time.Sleep(5 * time.Second)

	// block for concurrent writes
	defer store.hashLock.Unlock()
	store.hashLock.Lock()
	store.hashes[id] = hashed

	// mark storage as completed
	store.wg.Done()
	log.Printf("%d stored", id)
}

// storePassword imposes a 5-second delay, making the given password hash available by its id after that.
// FIXME: This implementation relies on the goroutine callstack as storage for the hash and id.
//        If this feels too implied, maybe use a channel instead?
func (store *passwordHashStore) storePassword(hashed string, id int64) {
	go store.delayStore(hashed, id)
}

// retrievePassword will attempt to find a stored password hash, returning empty if not found.
func (store *passwordHashStore) retrievePassword(id int64) string {
	log.Printf("Getting for %d", id)

	// blocks if storage is being writen to, but fast(er) for concurrent reads
	defer store.hashLock.RUnlock()
	store.hashLock.RLock()
	if password, ok := store.hashes[id]; ok {
		return password
	}
	log.Printf("No password hash for %d", id)
	return ""
}

// waitPendingStores should be called from a consumer of this store to ensure no pending writes exist.
func (store *passwordHashStore) waitPendingStores() {
	store.wg.Wait()
	log.Print("No more pending stores")
}