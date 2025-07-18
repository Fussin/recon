package scanner

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// Common utility functions used across all scanners

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

func isHTTPError(resp *http.Response) bool {
	return resp.StatusCode >= 400
}

func extractDomain(url string) string {
	// Extract domain from URL
	// Implementation here
	return ""
}

type VulnerabilityContext struct {
	Type         string
	RequiresAuth bool
	Complexity   string
}

func calculateSeverity(vuln *Vulnerability, context *VulnerabilityContext) string {
	// CVSS-based severity calculation
	score := 0.0

	// Base metrics
	if context.Type == "RCE" || context.Type == "SQL Injection" {
		score += 9.0
	} else if context.Type == "XSS" || context.Type == "XXE" {
		score += 7.0
	} else if context.Type == "IDOR" || context.Type == "SSRF" {
		score += 6.0
	} else {
		score += 4.0
	}

	// Adjust based on context
	if context.RequiresAuth {
		score -= 1.0
	}

	if context.Complexity == "High" {
		score -= 1.0
	}

	// Map to severity
	if score >= 9.0 {
		return "Critical"
	} else if score >= 7.0 {
		return "High"
	} else if score >= 4.0 {
		return "Medium"
	}
	return "Low"
}
