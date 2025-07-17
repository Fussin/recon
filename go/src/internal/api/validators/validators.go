package validators

import (
	"fmt"
	"net/url"
)

// ValidateURL validates a URL.
func ValidateURL(rawURL string) error {
	// Parse the URL.
	_, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	return nil
}
