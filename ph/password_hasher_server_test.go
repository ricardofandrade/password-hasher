package ph

import (
	"testing"
)

func TestGenerateStats2(t *testing.T) {
	stats := newPasswordHasherStats()
	total, avg := stats.generateStats()
	if total != 0 || avg != 0 {
		t.Errorf("Unexpect values for blank stats: %d total, avg %d", total, avg)
	}
}

// func Test(t *testing.T) {}
// func Test(t *testing.T) {}
// func Test(t *testing.T) {}
// func Test(t *testing.T) {}
// func Test(t *testing.T) {}
// func Test(t *testing.T) {}
// func Test(t *testing.T) {}
// func Test(t *testing.T) {}
