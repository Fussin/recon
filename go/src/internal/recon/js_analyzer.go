package recon

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
)

// JSAnalyzer is a struct for analyzing JavaScript files.
type JSAnalyzer struct {
}

// NewJSAnalyzer creates a new JSAnalyzer.
func NewJSAnalyzer() *JSAnalyzer {
	return &JSAnalyzer{}
}

// Analyze analyzes the JavaScript files of the given URL.
func (j *JSAnalyzer) Analyze(url string) ([]string, error) {
	// Make a request to the URL.
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the body of the response.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// A regular expression to find all the JavaScript files.
	re := regexp.MustCompile(`<script src="(.*?)"`)
	// Find all the matches.
	matches := re.FindAllStringSubmatch(string(body), -1)

	// A list to store the results.
	var results []string
	// Iterate over the matches and add the JavaScript files to the results.
	for _, match := range matches {
		results = append(results, match[1])
	}

	// A regular expression to find all the API endpoints.
	re = regexp.MustCompile(`fetch\(['"](.*?)['"]`)
	// Find all the matches.
	matches = re.FindAllStringSubmatch(string(body), -1)

	// Iterate over the matches and add the API endpoints to the results.
	for _, match := range matches {
		results = append(results, match[1])
	}

	return results, nil
}

// Endpoint represents an API endpoint.
type Endpoint struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

// FindEndpoints finds the API endpoints in the given JavaScript file.
func (j *JSAnalyzer) FindEndpoints(url string) ([]Endpoint, error) {
	// Make a request to the URL.
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the body of the response.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// A regular expression to find all the API endpoints.
	re := regexp.MustCompile(`fetch\(['"](.*?)['"], { method: ['"](.*?)['"] }`)
	// Find all the matches.
	matches := re.FindAllStringSubmatch(string(body), -1)

	// A list to store the results.
	var results []Endpoint
	// Iterate over the matches and add the API endpoints to the results.
	for _, match := range matches {
		results = append(results, Endpoint{
			URL:    match[1],
			Method: match[2],
		})
	}

	return results, nil
}
