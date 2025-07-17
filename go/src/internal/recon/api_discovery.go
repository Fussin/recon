package recon

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
)

// APIDiscovery is a struct for discovering API endpoints.
type APIDiscovery struct {
}

// NewAPIDiscovery creates a new APIDiscovery.
func NewAPIDiscovery() *APIDiscovery {
	return &APIDiscovery{}
}

// Discover discovers the API endpoints of the given URL.
func (a *APIDiscovery) Discover(url string) ([]string, error) {
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
	re := regexp.MustCompile(`fetch\(['"](.*?)['"]`)
	// Find all the matches.
	matches := re.FindAllStringSubmatch(string(body), -1)

	// A list to store the results.
	var results []string
	// Iterate over the matches and add the API endpoints to the results.
	for _, match := range matches {
		results = append(results, match[1])
	}

	// A regular expression to find all the links.
	re = regexp.MustCompile(`<a href="(.*?)"`)
	// Find all the matches.
	matches = re.FindAllStringSubmatch(string(body), -1)

	// Iterate over the matches and add the links to the results.
	for _, match := range matches {
		results = append(results, match[1])
	}

	return results, nil
}
