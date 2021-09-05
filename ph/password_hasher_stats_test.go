package ph

import (
	"bytes"
	"log"
	"testing"
	"time"
)

func Test_newPasswordHasherStats(t *testing.T) {
	stats := newPasswordHasherStats(nil)
	if stats.queue == nil {
		t.Error("Queue expected to not be nil")
	}
	if stats.times == nil {
		t.Error("Times expected to not be nil")
	}

	// Enforce channel len 1
	stats.queue <- 1

	full := false
	select {
	case stats.queue <- 2: // Put 2 in the channel unless it is full
	default:
		full = true
	}
	if !full {
		t.Error("Expected queue to hold only a single value")
	}
}

func Test_generateStatsIsEmpty(t *testing.T) {
	stats := newPasswordHasherStats(nil)
	total, avg := stats.generateStats()
	if total != 0 {
		t.Errorf("Unexpect values for blank stats: %d total", total)
	}
	if avg != 0 {
		t.Errorf("Unexpect values for blank stats: avg %d", avg)
	}
}

func forceGoroutineScheduler() {
	// FIXME: cheapest solution - might break tests on slow HW
	time.Sleep(time.Second / 100)
}

func Test_accumulateStatsLogs(t *testing.T) {
	buf := &bytes.Buffer{}
	stats := newPasswordHasherStats(log.New(buf, "", 0))
	stats.startAccumulating()

	forceGoroutineScheduler()
	if buf.String() != "Collecting stats...\n" {
		t.Errorf("Expected log on start: %s", buf.String())
	}

	buf.Reset()
	stats.stopAccumulating()
	forceGoroutineScheduler()
	if buf.String() != "Done collecting stats\n" {
		t.Errorf("Expected log on stop: %s", buf.String())
	}
}

func Test_accumulateTiming(t *testing.T) {
	buf := &bytes.Buffer{}
	stats := newPasswordHasherStats(log.New(buf, "", 0))
	stats.startAccumulating()
	forceGoroutineScheduler() // for logging
	buf.Reset()

	stats.accumulateTiming(time.Microsecond * 3)
	forceGoroutineScheduler()

	if len(stats.times) != 1 {
		t.Error("Expected one timing accumulated")
	} else if stats.times[0] != 3 {
		t.Error("Expected accumulated timing to be 3 ms")
	} else if buf.String() != "Elapsed time: 3ms\n" {
		t.Errorf("Expected logged timing to be 3 ms: %s", buf.String())
	}
	stats.stopAccumulating()
}

func Test_generateStats(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := log.New(buf, "", 0)

	stats := newPasswordHasherStats(logger)
	stats.startAccumulating()

	stats.accumulateTiming(time.Microsecond * 3)
	forceGoroutineScheduler()

	total, avg := stats.generateStats()
	if total != 1 {
		t.Error("Expected one timing accumulated")
	} else if avg != 3 {
		t.Error("Expected average timing to be 3 ms")
	}

	stats.accumulateTiming(time.Microsecond * 7)
	forceGoroutineScheduler()

	total, avg = stats.generateStats()
	if total != 2 {
		t.Error("Expected two timings accumulated")
	} else if avg != 5 {
		t.Error("Expected average timing to be 5 ms")
	}
	stats.stopAccumulating()
}
