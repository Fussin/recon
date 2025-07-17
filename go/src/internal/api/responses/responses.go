package responses

import (
	"encoding/json"
	"net/http"
)

// Response is a struct for API responses.
type Response struct {
	// The status of the response.
	Status string `json:"status"`
	// The data of the response.
	Data interface{} `json:"data"`
}

// NewResponse creates a new Response.
func NewResponse(status string, data interface{}) *Response {
	return &Response{
		Status: status,
		Data:   data,
	}
}

// Send sends the response.
func (r *Response) Send(w http.ResponseWriter, statusCode int) {
	// Set the content type.
	w.Header().Set("Content-Type", "application/json")
	// Set the status code.
	w.WriteHeader(statusCode)
	// Encode the response.
	json.NewEncoder(w).Encode(r)
}
