package unit

import (
	"testing"

	"github.com/autonomouspen/autonomouspen-ai/internal/recon"
	"github.com/stretchr/testify/assert"
)

func TestRecon(t *testing.T) {
	// Create a new recon engine.
	engine, err := recon.NewEngine(nil)
	assert.NoError(t, err)

	// Enumerate subdomains.
	subdomains, err := engine.Enumerate("example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, subdomains)

	// Discover endpoints.
	endpoints, err := engine.Discover("https://example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, endpoints)

	// Fingerprint technologies.
	technologies, err := engine.Fingerprint("https://example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, technologies)

	// Scan ports.
	ports, err := engine.Scan("example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, ports)

	// Map assets.
	err = engine.MapAssets("example.com")
	assert.NoError(t, err)
}
