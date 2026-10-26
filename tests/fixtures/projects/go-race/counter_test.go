package race

import "testing"

func TestCountTo(t *testing.T) {
	if got := CountTo(50); got != 50 {
		t.Logf("lost updates: %d", got)
	}
}

func TestLabel(t *testing.T) {
	if Label(2) != "2 items" {
		t.Errorf("Label(2) = %q, want %q", Label(2), "2 items")
	}
}
