package ph

import (
	"log"
	"sync"
	"time"
)

type microseconds int64

// passwordHasherStats accumulates the stats for the password hashing operations.
// These stats include the total number of operations as well as their individual timings in microseconds.
// FIXME: There's currently no strategy to rotate or purge the accumulated timings.
//        This accumulation is a risk and makes the service prone to Denial of Service due to exhausted memory.
type passwordHasherStats struct {
	queue chan microseconds
	times []microseconds
	lock  sync.RWMutex
}

// newPasswordHasherStats returns a new stats controller.
func newPasswordHasherStats() *passwordHasherStats {
	return &passwordHasherStats{
		queue: make(chan microseconds, 1),
		times: make([]microseconds, 0),
	}
}

// accumulateTiming stores the timing of a single password hash operation.
func (phStats *passwordHasherStats) accumulateTiming(elapsed time.Duration) {
	// TODO: This shouldn't block, unless storing states gets slow (too many entries?)
	//       Consider increasing the channel capacity - or make storing faster
	phStats.queue <- microseconds(elapsed.Microseconds())
}

// generateStats returns the total number of operations and their average timing in microseconds.
func (phStats *passwordHasherStats) generateStats() (total int64, avg int64) {
	// Lock ensures that the total won't change during the loop
	defer phStats.lock.RUnlock()
	phStats.lock.RLock()
	if len(phStats.times) == 0 {
		return
	}
	var accumulated microseconds
	for _, ms := range phStats.times {
		accumulated += ms
	}
	// coincidentally, len = total, since we never purge timings
	total = int64(len(phStats.times))
	return total, int64(accumulated) / total
}

// accumulateStats actually accumulate timings sent by accumulateTiming.
func (phStats *passwordHasherStats) accumulateStats() {
	log.Print("Collecting stats...")
	ok := true
	for ok {
		var ms microseconds
		if ms, ok = <-phStats.queue; ok {
			log.Printf("Elapsed time: %dms", ms)

			// block reads while appending/resizing/reallocating
			phStats.lock.Lock()
			phStats.times = append(phStats.times, ms)
			phStats.lock.Unlock()
		}
	}
	log.Print("Done collecting stats")
}

// startAccumulating begins to accumulate timings.
func (phStats *passwordHasherStats) startAccumulating() {
	go phStats.accumulateStats()
}

// stopAccumulating interrupts the accumulation of timings.
func (phStats *passwordHasherStats) stopAccumulating() {
	close(phStats.queue)
}
