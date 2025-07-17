package recon

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// HistoricalData is a struct for finding historical data.
type HistoricalData struct {
}

// NewHistoricalData creates a new HistoricalData.
func NewHistoricalData() *HistoricalData {
	return &HistoricalData{}
}

// WaybackMachine searches the Wayback Machine for the given domain.
func (h *HistoricalData) WaybackMachine(domain string) ([]string, error) {
	// The URL for the Wayback Machine API.
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)
	// Make a request to the API.
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Decode the JSON response.
	var results [][]string
	err = json.NewDecoder(resp.Body).Decode(&results)
	if err != nil {
		return nil, err
	}

	// A list to store the URLs.
	var urls []string
	// Iterate over the results and add the URLs to the list.
	for _, result := range results {
		if len(result) > 0 {
			urls = append(urls, result[0])
		}
	}

	return urls, nil
}

// GitHubSearch searches GitHub for the given domain.
func (h *HistoricalData) GitHubSearch(domain string) ([]string, error) {
	// The URL for the GitHub API.
	url := fmt.Sprintf("https://api.github.com/search/code?q=%s", domain)
	// Make a request to the API.
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Decode the JSON response.
	var results struct {
		Items []struct {
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	err = json.NewDecoder(resp.Body).Decode(&results)
	if err != nil {
		return nil, err
	}

	// A list to store the URLs.
	var urls []string
	// Iterate over the results and add the URLs to the list.
	for _, item := range results.Items {
		urls = append(urls, item.HTMLURL)
	}

	return urls, nil
}
