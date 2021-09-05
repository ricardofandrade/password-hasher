package ph

import (
	"bytes"
	"log"
	"testing"
	"time"
)

func Test_newPasswordHashStore(t *testing.T) {
	store := newPasswordHashStore(nil, 0)
	if store.hashes == nil {
		t.Error("Hashes expected to not be nil")
	}
}

func Test_retrievePasswordEmpty(t *testing.T) {
	buf := &bytes.Buffer{}
	store := newPasswordHashStore(log.New(buf, "", 0), 0)
	if store.retrievePassword(0) != "" {
		t.Error("Expected an empty store to return no hashes")
	}
	if buf.String() != "Getting for 0\nNo password hash for 0\n" {
		t.Error("Expected log to indicate no hashes")
	}
}

func Test_delayStore(t *testing.T) {
	// test with no delay
	buf := &bytes.Buffer{}
	store := newPasswordHashStore(log.New(buf, "", 0), 0)
	store.delayStore("test", 0)

	if len(store.hashes) != 1 {
		t.Error("Expected one hash")
	} else if hash, ok := store.hashes[0]; !ok {
		t.Error("Expected hash with id 0")
	} else if hash != "test" {
		t.Errorf("Expected correct value, got %s", hash)
	}

	if buf.String() != "Storing for 0...\n0 stored\n" {
		t.Errorf("Expected log indicating ongoing work: %s", buf.String())
	}

	// shouldn't block
	store.waitPendingStores()
}

func Test_retrievePassword(t *testing.T) {
	// test with no delay
	buf := &bytes.Buffer{}
	store := newPasswordHashStore(log.New(buf, "", 0), 0)
	store.delayStore("test", 0)
	buf.Reset()

	hash := store.retrievePassword(0)
	if hash != "test" {
		t.Errorf("Expected to return correct hash, got %s", hash)
	}
	if buf.String() != "Getting for 0\n" {
		t.Errorf("Expected log to not indicate problems: %s", buf.String())
	}
}

func Test_storePassword(t *testing.T) {
	// test with small delay
	delay := time.Second / 100

	buf := &bytes.Buffer{}
	store := newPasswordHashStore(log.New(buf, "", 0), delay)
	store.storePassword("test", 0)
	forceGoroutineScheduler()
	if store.retrievePassword(0) != "" {
		t.Error("Expected to have no hashes before the delay")
	}
	buf.Reset()

	store.waitPendingStores()
	if store.retrievePassword(0) != "test" {
		t.Error("Expected to have correct hash before the delay")
	}

	if buf.String() != "0 stored\nNo more pending stores\nGetting for 0\n" {
		t.Errorf("Expected log indicating no more pending: %s", buf.String())
	}
}
