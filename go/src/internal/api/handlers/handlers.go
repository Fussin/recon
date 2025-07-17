package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/autonomouspen/autonomouspen-ai/internal/core"
	"github.com/gorilla/mux"
)

// API is a struct for the API.
type API struct {
	// The scanning engine.
	engine *core.Engine
}

// NewAPI creates a new API.
func NewAPI(engine *core.Engine) *API {
	return &API{
		engine: engine,
	}
}

// RegisterRoutes registers the API routes.
func (a *API) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/scan", a.scanHandler).Methods("POST")
}

// scanHandler handles scan requests.
func (a *API) scanHandler(w http.ResponseWriter, r *http.Request) {
	// Decode the request body.
	var req struct {
		Target string `json:"target"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Perform the scan.
	err = a.engine.Scan(req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send the response.
	w.WriteHeader(http.StatusOK)
}
