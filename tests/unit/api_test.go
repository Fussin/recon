package unit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/autonomouspen/autonomouspen-ai/internal/api/handlers"
	"github.com/autonomouspen/autonomouspen-ai/internal/database"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestAPI(t *testing.T) {
	// Create a new in-memory database.
	db, err := database.NewDB("file::memory:")
	assert.NoError(t, err)

	// Migrate the database.
	err = db.Migrate()
	assert.NoError(t, err)

	// Create a new vulnerability repo.
	repo := database.NewVulnerabilityRepo(db)

	// Create a new vulnerability handler.
	handler := handlers.NewVulnerabilityHandlers(repo)

	// Create a new router.
	r := mux.NewRouter()

	// Register the routes.
	handler.RegisterRoutes(r)

	// Create a new vulnerability.
	v := &database.Vulnerability{
		ScanID:      1,
		Plugin:      "test",
		Description: "test",
		Severity:    "High",
	}
	body, err := json.Marshal(v)
	assert.NoError(t, err)

	// Create a new request.
	req, err := http.NewRequest("POST", "/api/v1/vulnerabilities", bytes.NewBuffer(body))
	assert.NoError(t, err)

	// Create a new response recorder.
	rr := httptest.NewRecorder()

	// Serve the request.
	r.ServeHTTP(rr, req)

	// Check the status code.
	assert.Equal(t, http.StatusCreated, rr.Code)
}
