package scanner

import (
	"fmt"
	"net/http"
)

// Scanner is the interface that all scanners must implement.
type Scanner interface {
	// Scan performs a scan of the given target.
	Scan(target string) ([]*Vulnerability, error)
}

// BaseScanner is a base scanner that provides common functionality.
type BaseScanner struct {
	// The HTTP client to use for making requests.
	client *http.Client
}

// NewBaseScanner creates a new BaseScanner.
func NewBaseScanner() *BaseScanner {
	return &BaseScanner{
		client: &http.Client{},
	}
}

// Scan performs a scan of the given target.
func (s *BaseScanner) Scan(target string) ([]*Vulnerability, error) {
	// This method should be implemented by the specific scanner.
	return nil, fmt.Errorf("not implemented")
}

// Get performs a GET request to the given URL.
func (s *BaseScanner) Get(url string) (*http.Response, error) {
	// Create a new request.
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set the User-Agent header.
	req.Header.Set("User-Agent", "AUTONOMOUSPEN AI")

	// Perform the request.
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Post performs a POST request to the given URL.
func (s *BaseScanner) Post(url string, body []byte) (*http.Response, error) {
	// Create a new request.
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}

	// Set the User-Agent header.
	req.Header.Set("User-Agent", "AUTONOMOUSPEN AI")

	// Set the body of the request.
	req.Body = http.NoBody

	// Perform the request.
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Vulnerability represents a single vulnerability.
type Vulnerability struct {
	// The name of the vulnerability.
	Name string `json:"name"`
	// A description of the vulnerability.
	Description string `json:"description"`
	// The severity of the vulnerability.
	Severity string `json:"severity"`
	// The CWE ID of the vulnerability.
	CWE string `json:"cwe"`
	// The CVE ID of the vulnerability.
	CVE string `json:"cve"`
	// The CVSS score of the vulnerability.
	CVSS float64 `json:"cvss"`
	// The evidence for the vulnerability.
	Evidence string `json:"evidence"`
}
