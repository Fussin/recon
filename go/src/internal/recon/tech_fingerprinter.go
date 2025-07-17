package recon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// TechFingerprinter is a struct for fingerprinting technologies.
type TechFingerprinter struct {
}

// NewTechFingerprinter creates a new TechFingerprinter.
func NewTechFingerprinter() *TechFingerprinter {
	return &TechFingerprinter{}
}

// Fingerprint fingerprints the technologies of the given URL.
func (t *TechFingerprinter) Fingerprint(url string) (map[string]interface{}, error) {
	// Make a request to the URL.
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// A map to store the results.
	results := make(map[string]interface{})

	// Check the headers for technology information.
	for key, values := range resp.Header {
		for _, value := range values {
			if strings.Contains(strings.ToLower(key), "x-powered-by") {
				results["x-powered-by"] = value
			}
			if strings.Contains(strings.ToLower(key), "server") {
				results["server"] = value
			}
		}
	}

	// Check the body for technology information.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Check for common JavaScript libraries.
	if strings.Contains(string(body), "jquery") {
		results["jquery"] = true
	}
	if strings.Contains(string(body), "react") {
		results["react"] = true
	}
	if strings.Contains(string(body), "angular") {
		results["angular"] = true
	}
	if strings.Contains(string(body), "vue") {
		results["vue"] = true
	}

	// Check for common CMSs.
	if strings.Contains(string(body), "wp-content") {
		results["wordpress"] = true
	}
	if strings.Contains(string(body), "joomla") {
		results["joomla"] = true
	}
	if strings.Contains(string(body), "drupal") {
		results["drupal"] = true
	}

	return results, nil
}

// Wappalyzer is a struct for using the Wappalyzer API.
type Wappalyzer struct {
	apiKey string
}

// NewWappalyzer creates a new Wappalyzer.
func NewWappalyzer(apiKey string) *Wappalyzer {
	return &Wappalyzer{
		apiKey: apiKey,
	}
}

// Fingerprint fingerprints the technologies of the given URL using the Wappalyzer API.
func (w *Wappalyzer) Fingerprint(url string) (map[string]interface{}, error) {
	// The URL for the Wappalyzer API.
	apiUrl := fmt.Sprintf("https://api.wappalyzer.com/v2/lookup/?url=%s&key=%s", url, w.apiKey)
	// Make a request to the API.
	resp, err := http.Get(apiUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Decode the JSON response.
	var results map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&results)
	if err != nil {
		return nil, err
	}

	return results, nil
}
