package ph

import (
	"testing"
)

func TestGenerateStats(t *testing.T) {
	stats := newPasswordHasherStats()
	total, avg := stats.generateStats()
	if total != 0 || avg != 0 {
		t.Errorf("Unexpect values for blank stats: %d total, avg %d", total, avg)
	}
}
