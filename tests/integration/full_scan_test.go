package integration

import (
	"testing"

	"github.com/autonomouspen/autonomouspen-ai/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestFullScan(t *testing.T) {
	// Create a new scanner engine.
	engine, err := scanner.NewEngine(nil)
	assert.NoError(t, err)

	// Initialize the engine.
	err = engine.InitializeEngine()
	assert.NoError(t, err)

	// Start the engine.
	engine.ManageWorkerPool()

	// Scan a target.
	err = engine.ScanTarget("https://example.com")
	assert.NoError(t, err)
}
