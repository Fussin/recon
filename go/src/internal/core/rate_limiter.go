package core

import "time"

// RateLimiter is a struct for rate limiting.
type RateLimiter struct {
	// A channel to receive tokens.
	tokens chan bool
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter(rate int) *RateLimiter {
	// Create a new rate limiter.
	limiter := &RateLimiter{
		tokens: make(chan bool, rate),
	}

	// Start a goroutine to fill the token bucket.
	go func() {
		for {
			limiter.tokens <- true
			time.Sleep(time.Second / time.Duration(rate))
		}
	}()

	return limiter
}

// Wait waits for a token.
func (l *RateLimiter) Wait() {
	<-l.tokens
}
