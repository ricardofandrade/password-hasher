package ph

import (
	"testing"
)

var phHasher = NewPasswordHasher()

func TestGenerateStats(t *testing.T) {
	empty := Stats{}
	stats := phHasher.generateStats()
	if stats != empty {
		t.Fail()
	}
}
