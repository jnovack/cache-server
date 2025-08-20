package logging

import "testing"

// TestSetupCalls ensures Setup can be called with different log levels without panic.
func TestSetupLevels(t *testing.T) {
	levels := []string{"debug", "info", "warn", "error", "invalid"}
	for _, l := range levels {
		Setup(l) // just assert no panic
	}
}
