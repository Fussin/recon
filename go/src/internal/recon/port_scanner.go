package recon

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// PortScanner is a struct for scanning ports.
type PortScanner struct {
	// A channel to receive the results.
	results chan int
	// A wait group to wait for all the workers to finish.
	wg *sync.WaitGroup
}

// NewPortScanner creates a new PortScanner.
func NewPortScanner() *PortScanner {
	return &PortScanner{
		results: make(chan int),
		wg:      &sync.WaitGroup{},
	}
}

// Scan scans the ports of the given host.
func (p *PortScanner) Scan(host string, ports []int) ([]int, error) {
	// Create a worker pool to perform the port scans.
	for i := 0; i < 100; i++ {
		p.wg.Add(1)
		go p.worker(host, ports)
	}

	// A list to store the results.
	var results []int
	// A map to keep track of the results we've already seen.
	seen := make(map[int]bool)

	// A goroutine to read the results from the channel.
	go func() {
		for result := range p.results {
			// If we haven't seen this result before, add it to the list.
			if _, ok := seen[result]; !ok {
				results = append(results, result)
				seen[result] = true
			}
		}
	}()

	// Wait for all the workers to finish.
	p.wg.Wait()
	// Close the results channel.
	close(p.results)

	return results, nil
}

// worker is a worker that performs port scans.
func (p *PortScanner) worker(host string, ports []int) {
	defer p.wg.Done()

	// Iterate over the ports and perform a port scan for each one.
	for _, port := range ports {
		// Create the full address.
		address := fmt.Sprintf("%s:%d", host, port)
		// Perform the port scan.
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			// If the scan was successful, send the result to the channel.
			p.results <- port
			conn.Close()
		}
	}
}
