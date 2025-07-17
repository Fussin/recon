package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEngine(t *testing.T) {
	// Create a new engine.
	engine, err := NewEngine(nil)
	assert.NoError(t, err)

	// Start the engine.
	engine.Start()

	// Perform a scan.
	err = engine.Scan("https://example.com")
	assert.NoError(t, err)

	// Wait for the scan to complete.
	time.Sleep(2 * time.Second)

	// Stop the engine.
	engine.Stop()
}
