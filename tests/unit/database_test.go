package unit

import (
	"testing"

	"github.com/autonomouspen/autonomouspen-ai/internal/database"
	"github.com/stretchr/testify/assert"
)

func TestDatabase(t *testing.T) {
	// Create a new in-memory database.
	db, err := database.NewDB("file::memory:")
	assert.NoError(t, err)

	// Migrate the database.
	err = db.Migrate()
	assert.NoError(t, err)

	// Create a new vulnerability.
	v := &database.Vulnerability{
		ScanID:      1,
		Plugin:      "test",
		Description: "test",
		Severity:    "High",
	}
	err = db.Create(v).Error
	assert.NoError(t, err)

	// Get the vulnerability.
	var v2 database.Vulnerability
	err = db.First(&v2, v.ID).Error
	assert.NoError(t, err)
	assert.Equal(t, v.Plugin, v2.Plugin)
}
