package modules

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/autonomouspen/scanner/internal/scanner"
)

type XXEScanner struct {
	client   *http.Client
	config   *XXEConfig
	oob      *OOBListener
	payloads map[string][]XXEPayload
}

type XXEConfig struct {
	OOBDomain string
}

type XXEPayload struct {
	Name     string
	XML      string
	Expected []string
	Type     string
	DTD      string
	EntityReference string
}

type VulnerabilityEvidence struct {
	PayloadUsed   string
	HTTPStatus    int
	ResponseSize  int
	Headers       http.Header
	Type          string
	Confidence    string
	ExtractedData string
	ErrorMessages []string
	ResponseTime  time.Duration
}

type XXEReport struct {
	Summary         XXESummary
	Vulnerabilities map[string]*VulnerabilityDetails
}

type XXESummary struct {
	TotalEndpoints int
	VulnEndpoints  int
	RiskLevel      string
}

type VulnerabilityDetails struct {
	Vulnerability *scanner.Vulnerability
	Impact        string
	Remediation   string
	References    []string
}

type OOBCallback struct {
	Triggered   bool
	HTTPRequest *http.Request
	Timestamp   time.Time
	Data        string
}

type OOBListener struct {
	Domain     string
	HTTPServer *http.Server
	DNSServer  *http.Server // Simplified for this example
	callbacks  map[string]*OOBCallback
	mutex      sync.RWMutex
}

func NewXXEScanner(config *XXEConfig) *XXEScanner {
	scanner := &XXEScanner{
		client: &http.Client{},
		config: config,
	}
	scanner.oob = scanner.setupOOBDetection()
	scanner.payloads = scanner.generateAdvancedPayloads()
	return scanner
}

func (s *XXEScanner) Scan(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	xmlEndpoints := s.findXMLEndpoints(target)

	for _, endpoint := range xmlEndpoints {
		s.testContextualXXE(ctx, endpoint, results)
	}
}

func (s *XXEScanner) findXMLEndpoints(target *Target) []*XMLEndpoint {
	var endpoints []*XMLEndpoint

	resp, err := s.client.Get(target.URL)
	if err != nil {
		return endpoints
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return endpoints
	}

	doc.Find("a").Each(func(i int, sel *goquery.Selection) {
		href, exists := sel.Attr("href")
		if exists {
			if strings.HasSuffix(href, ".xml") {
				endpoints = append(endpoints, &XMLEndpoint{URL: href, Method: "GET"})
			}
		}
	})

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

func (s *XXEScanner) testContextualXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// Simplified context detection
	if strings.Contains(endpoint.URL, "soap") {
		s.testSOAPSpecificXXE(ctx, endpoint, results)
	} else {
		s.testGenericXXE(ctx, endpoint, results)
	}
}

func (s *XXEScanner) testGenericXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	for _, payload := range s.payloads["file_disclosure"] {
		s.executeTest(ctx, endpoint, payload, results)
	}
	for _, payload := range s.payloads["ssrf"] {
		s.executeTest(ctx, endpoint, payload, results)
	}
}

func (s *XXEScanner) testSOAPSpecificXXE(ctx context.Context, endpoint *XMLEndpoint, results chan<- *scanner.Vulnerability) {
	// Implementation for SOAP-specific XXE tests
}

func (s *XXEScanner) executeTest(ctx context.Context, endpoint *XMLEndpoint, payload XXEPayload, results chan<- *scanner.Vulnerability) {
	req, err := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBufferString(payload.XML))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if evidence := s.analyzeResponse(resp, payload); evidence != nil {
		results <- &scanner.Vulnerability{
			Name:        "XXE",
			Severity:    "High",
			Description: fmt.Sprintf("XXE vulnerability of type '%s' detected at %s", evidence.Type, endpoint.URL),
			Evidence:    fmt.Sprintf("Payload: %s, Confidence: %s", evidence.PayloadUsed, evidence.Confidence),
		}
	}
}

func (s *XXEScanner) analyzeResponse(resp *http.Response, payload XXEPayload) *VulnerabilityEvidence {
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	evidence := &VulnerabilityEvidence{
		PayloadUsed:  payload.Name,
		HTTPStatus:   resp.StatusCode,
		ResponseSize: len(body),
		Headers:      resp.Header,
	}

	if s.detectFileDisclosure(bodyStr, payload.Expected) {
		evidence.Type = "file_disclosure"
		evidence.Confidence = "high"
		evidence.ExtractedData = s.extractSensitiveData(bodyStr)
		return evidence
	}

	if s.detectXMLErrors(bodyStr) {
		evidence.Type = "error_based"
		evidence.Confidence = "medium"
		evidence.ErrorMessages = s.extractErrorMessages(bodyStr)
		return evidence
	}

	return nil
}

func (s *XXEScanner) detectFileDisclosure(body string, expected []string) bool {
	for _, expect := range expected {
		if strings.Contains(body, expect) {
			return true
		}
	}
	patterns := []string{
		`root:x:\d+:\d+:`,
		`\[boot loader\]`,
		`#.*localhost`,
		`<\?xml.*encoding.*\?>`,
		`java\..*Exception`,
		`System\..*\..*`,
	}
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			return true
		}
	}
	return false
}

func (s *XXEScanner) extractSensitiveData(body string) string {
	// Implementation for extracting sensitive data
	return ""
}

func (s *XXEScanner) detectXMLErrors(body string) bool {
	// Implementation for detecting XML errors
	return false
}

func (s *XXEScanner) extractErrorMessages(body string) []string {
	// Implementation for extracting error messages
	return nil
}

func (s *XXEScanner) setupOOBDetection() *OOBListener {
	listener := &OOBListener{
		Domain:    s.config.OOBDomain,
		callbacks: make(map[string]*OOBCallback),
	}
	listener.HTTPServer = &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(listener.handleHTTPCallback),
	}
	go listener.HTTPServer.ListenAndServe()
	return listener
}

func (l *OOBListener) handleHTTPCallback(w http.ResponseWriter, r *http.Request) {
	callbackID := r.URL.Query().Get("id")
	if callbackID == "" {
		return
	}
	l.mutex.Lock()
	if callback, exists := l.callbacks[callbackID]; exists {
		callback.Triggered = true
		callback.HTTPRequest = r
		callback.Timestamp = time.Now()
		callback.Data = r.URL.Query().Get("data")
	}
	l.mutex.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (s *XXEScanner) generateAdvancedPayloads() map[string][]XXEPayload {
	return map[string][]XXEPayload{
		"file_disclosure": s.generateFileDisclosurePayloads(),
		"ssrf":            s.generateSSRFPayloads(),
		"dos":             s.generateDOSPayloads(),
		"rce":             s.generateRCEPayloads(),
		"oob_exfiltration": s.generateOOBPayloads(),
	}
}

func (s *XXEScanner) generateFileDisclosurePayloads() []XXEPayload {
	// Implementation for generating file disclosure payloads
	return nil
}

func (s *XXEScanner) generateSSRFPayloads() []XXEPayload {
	// Implementation for generating SSRF payloads
	return nil
}

func (s *XXEScanner) generateDOSPayloads() []XXEPayload {
	// Implementation for generating DoS payloads
	return nil
}

func (s *XXEScanner) generateRCEPayloads() []XXEPayload {
	// Implementation for generating RCE payloads
	return nil
}

func (s *XXEScanner) generateOOBPayloads() []XXEPayload {
	// Implementation for generating OOB payloads
	return nil
}

func (s *XXEScanner) generateEvasionPayloads() []XXEPayload {
	// Implementation for generating evasion payloads
	return nil
}

func (s *XXEScanner) generateDetailedReport(vulns []*scanner.Vulnerability) *XXEReport {
	// Implementation for generating a detailed report
	return nil
}

func (s *XXEScanner) assessImpact(vuln *scanner.Vulnerability) string {
	// Implementation for assessing impact
	return ""
}

func (s *XXEScanner) generateRemediation(vuln *scanner.Vulnerability) string {
	// Implementation for generating remediation advice
	return ""
}

func (s *XXEScanner) getReferences() []string {
	// Implementation for getting references
	return nil
}

func (s *XXEScanner) calculateRiskLevel(vulns []*scanner.Vulnerability) string {
	// Implementation for calculating risk level
	return ""
}
