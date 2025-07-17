package recon

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// SubdomainEnumerator is a struct for enumerating subdomains.
type SubdomainEnumerator struct {
	// A set of resolvers to use for DNS lookups.
	resolvers []string
	// A channel to receive the results.
	results chan string
	// A wait group to wait for all the workers to finish.
	wg *sync.WaitGroup
}

// NewSubdomainEnumerator creates a new SubdomainEnumerator.
func NewSubdomainEnumerator(resolvers []string) *SubdomainEnumerator {
	return &SubdomainEnumerator{
		resolvers: resolvers,
		results:   make(chan string),
		wg:        &sync.WaitGroup{},
	}
}

// Enumerate enumerates the subdomains of the given domain.
func (s *SubdomainEnumerator) Enumerate(domain string) ([]string, error) {
	// A list of common subdomains to check for.
	subdomains := []string{
		"www",
		"mail",
		"ftp",
		"localhost",
		"webmail",
		"smtp",
		"pop",
		"ns1",
		"ns2",
		"ns3",
		"ns4",
	}

	// Create a worker pool to perform the DNS lookups.
	for i := 0; i < 10; i++ {
		s.wg.Add(1)
		go s.worker(domain, subdomains)
	}

	// A list to store the results.
	var results []string
	// A map to keep track of the results we've already seen.
	seen := make(map[string]bool)

	// A goroutine to read the results from the channel.
	go func() {
		for result := range s.results {
			// If we haven't seen this result before, add it to the list.
			if _, ok := seen[result]; !ok {
				results = append(results, result)
				seen[result] = true
			}
		}
	}()

	// Wait for all the workers to finish.
	s.wg.Wait()
	// Close the results channel.
	close(s.results)

	return results, nil
}

// worker is a worker that performs DNS lookups.
func (s *SubdomainEnumerator) worker(domain string, subdomains []string) {
	defer s.wg.Done()

	// Create a new resolver.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", s.resolvers[0])
		},
	}

	// Iterate over the subdomains and perform a DNS lookup for each one.
	for _, subdomain := range subdomains {
		// Create the full hostname.
		hostname := fmt.Sprintf("%s.%s", subdomain, domain)
		// Perform the DNS lookup.
		_, err := resolver.LookupHost(hostname)
		if err == nil {
			// If the lookup was successful, send the result to the channel.
			s.results <- hostname
		}
	}
}

// PermutationGenerator is a struct for generating permutations of subdomains.
type PermutationGenerator struct {
	// The characters to use for generating permutations.
	chars []rune
}

// NewPermutationGenerator creates a new PermutationGenerator.
func NewPermutationGenerator(chars string) *PermutationGenerator {
	return &PermutationGenerator{
		chars: []rune(chars),
	}
}

// Generate generates permutations of the given length.
func (p *PermutationGenerator) Generate(length int) []string {
	// A list to store the permutations.
	var permutations []string
	// A recursive function to generate the permutations.
	var generate func(int, []rune)
	generate = func(n int, runes []rune) {
		if n == 0 {
			permutations = append(permutations, string(runes))
			return
		}
		for _, char := range p.chars {
			generate(n-1, append(runes, char))
		}
	}
	generate(length, []rune{})
	return permutations
}

// CertificateTransparency is a struct for searching certificate transparency logs.
type CertificateTransparency struct {
}

// NewCertificateTransparency creates a new CertificateTransparency.
func NewCertificateTransparency() *CertificateTransparency {
	return &CertificateTransparency{}
}

// Search searches certificate transparency logs for the given domain.
func (c *CertificateTransparency) Search(domain string) ([]string, error) {
	// A list to store the results.
	var results []string
	// The URL for the crt.sh API.
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	// Make a request to the API.
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Decode the JSON response.
	var certs []struct {
		NameValue string `json:"name_value"`
	}
	err = json.NewDecoder(resp.Body).Decode(&certs)
	if err != nil {
		return nil, err
	}

	// Iterate over the certificates and add the subdomains to the results.
	for _, cert := range certs {
		// Split the name value by newlines.
		names := strings.Split(cert.NameValue, "\n")
		// Iterate over the names and add them to the results.
		for _, name := range names {
			results = append(results, name)
		}
	}

	return results, nil
}
