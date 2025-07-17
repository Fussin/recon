package middleware

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// LoggingMiddleware logs all requests.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the request.
		logrus.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
		}).Info("request received")

		// Call the next handler.
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware authenticates all requests.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the API key from the header.
		apiKey := r.Header.Get("X-API-Key")

		// Check if the API key is valid.
		if apiKey != "my-secret-api-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Call the next handler.
		next.ServeHTTP(w, r)
	})
}

// MetricsMiddleware collects metrics for all requests.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Start a timer.
		start := time.Now()

		// Call the next handler.
		next.ServeHTTP(w, r)

		// Log the duration.
		logrus.WithFields(logrus.Fields{
			"duration": time.Since(start),
		}).Info("request processed")
	})
}
