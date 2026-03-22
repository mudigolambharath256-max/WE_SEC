package transport

import (
	"context"
	"log"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter for probe execution.
// Thread-safe and supports dynamic rate adjustment during campaigns.
type RateLimiter struct {
	tokens       chan struct{}
	ticker       *time.Ticker
	rps          float64
	burst        int
	mu           sync.RWMutex
	stopChan     chan struct{}
	campaignID   string
}

// NewRateLimiter creates a new token bucket rate limiter.
//
// Args:
//   - requestsPerSecond: Maximum requests per second (e.g., 5.0 for 5 req/s)
//   - burst: Maximum burst size (number of tokens in bucket)
//
// Returns:
//   - *RateLimiter: Configured rate limiter instance
//
// The rate limiter starts immediately and runs in a background goroutine.
func NewRateLimiter(requestsPerSecond float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		tokens:   make(chan struct{}, burst),
		rps:      requestsPerSecond,
		burst:    burst,
		stopChan: make(chan struct{}),
	}

	// Pre-fill bucket with tokens
	for i := 0; i < burst; i++ {
		rl.tokens <- struct{}{}
	}

	// Calculate interval between tokens
	interval := time.Duration(float64(time.Second) / requestsPerSecond)
	rl.ticker = time.NewTicker(interval)

	// Start token generation goroutine
	go rl.run()

	log.Printf("[RateLimiter] Initialized: %.2f req/s, burst=%d", requestsPerSecond, burst)
	return rl
}

// run is the background goroutine that adds tokens to the bucket.
func (rl *RateLimiter) run() {
	for {
		select {
		case <-rl.ticker.C:
			// Try to add a token (non-blocking)
			select {
			case rl.tokens <- struct{}{}:
				// Token added successfully
			default:
				// Bucket is full, skip this token
			}
		case <-rl.stopChan:
			rl.ticker.Stop()
			return
		}
	}
}

// Wait blocks until a token is available or the context is cancelled.
//
// Args:
//   - ctx: Context for cancellation
//
// Returns:
//   - error: nil on success, context error if cancelled
//
// This method is called by every probe goroutine before making a request.
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		// Token acquired
		return nil
	case <-ctx.Done():
		// Context cancelled
		return ctx.Err()
	}
}

// SetRate dynamically adjusts the rate limit during a campaign.
//
// Args:
//   - rps: New requests per second rate
//
// This is useful for adaptive rate limiting based on target response times.
func (rl *RateLimiter) SetRate(rps float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rps == rl.rps {
		return
	}

	log.Printf("[RateLimiter] Rate adjusted: %.2f -> %.2f req/s", rl.rps, rps)

	// Stop old ticker
	rl.ticker.Stop()

	// Create new ticker with updated interval
	interval := time.Duration(float64(time.Second) / rps)
	rl.ticker = time.NewTicker(interval)

	rl.rps = rps
}

// Stop gracefully shuts down the rate limiter.
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
	log.Printf("[RateLimiter] Stopped")
}

// GetRate returns the current rate limit.
func (rl *RateLimiter) GetRate() float64 {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.rps
}
