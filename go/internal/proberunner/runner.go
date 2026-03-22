package proberunner

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/llmrt/llm-redteam/internal/proto"
	"github.com/llmrt/llm-redteam/internal/transport"
)

// Runner manages concurrent probe execution with rate limiting.
type Runner struct {
	concurrency int
	rateLimiter *transport.RateLimiter
	adapter     *transport.Adapter
	oobClient   *transport.OOBClient

	// Statistics
	totalProbes   int64
	successCount  int64
	errorCount    int64
	startTime     time.Time
}

// NewRunner creates a new probe runner.
//
// Args:
//   - concurrency: Number of concurrent probe goroutines
//   - rateLimiter: Rate limiter for throttling requests
//
// Returns:
//   - *Runner: Configured runner instance
func NewRunner(concurrency int, rateLimiter *transport.RateLimiter) *Runner {
	return &Runner{
		concurrency: concurrency,
		rateLimiter: rateLimiter,
		oobClient:   transport.NewOOBClient(),
		startTime:   time.Now(),
	}
}

// FireBatch executes a batch of probes concurrently.
//
// Args:
//   - ctx: Context for cancellation
//   - request: Batch request containing payloads and configuration
//   - results: Channel to send probe results
//
// Returns:
//   - error: If batch execution fails
//
// Creates a goroutine pool and processes payloads with rate limiting.
// Respects context cancellation via ctx.Done().
func (r *Runner) FireBatch(
	ctx context.Context,
	request *proto.ProbeBatchRequest,
	results chan<- *proto.ProbeResult,
) error {
	// Initialize adapter
	r.adapter = transport.NewAdapter(
		request.EndpointUrl,
		request.Method,
		request.BodySchema,
		request.Headers,
	)

	// Prepare payloads
	payloads := request.Payloads

	// Apply transformations
	var transformedPayloads []string
	for _, payload := range payloads {
		variants := r.generateVariants(payload, request)
		transformedPayloads = append(transformedPayloads, variants...)
	}

	log.Printf("[Runner] Starting batch: %d original payloads -> %d variants, concurrency=%d",
		len(payloads), len(transformedPayloads), r.concurrency)

	// Create worker pool
	poolSize := min(r.concurrency, len(transformedPayloads))
	payloadChan := make(chan string, len(transformedPayloads))
	var wg sync.WaitGroup

	// Start statistics goroutine
	stopStats := make(chan struct{})
	go r.logStatistics(stopStats)

	// Start workers
	for i := 0; i < poolSize; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			r.worker(ctx, workerID, payloadChan, request, results)
		}(i)
	}

	// Feed payloads to workers
	for _, payload := range transformedPayloads {
		select {
		case payloadChan <- payload:
		case <-ctx.Done():
			close(payloadChan)
			wg.Wait()
			close(stopStats)
			return ctx.Err()
		}
	}

	close(payloadChan)
	wg.Wait()
	close(stopStats)

	log.Printf("[Runner] Batch complete: total=%d, success=%d, errors=%d",
		atomic.LoadInt64(&r.totalProbes),
		atomic.LoadInt64(&r.successCount),
		atomic.LoadInt64(&r.errorCount))

	return nil
}

// worker processes payloads from the channel.
func (r *Runner) worker(
	ctx context.Context,
	workerID int,
	payloads <-chan string,
	request *proto.ProbeBatchRequest,
	results chan<- *proto.ProbeResult,
) {
	for {
		select {
		case payload, ok := <-payloads:
			if !ok {
				return
			}

			// Wait for rate limiter
			if err := r.rateLimiter.Wait(ctx); err != nil {
				log.Printf("[Worker %d] Rate limiter cancelled: %v", workerID, err)
				return
			}

			// Execute probe
			result := r.executeProbe(ctx, payload, request)
			atomic.AddInt64(&r.totalProbes, 1)

			if result.ErrorMessage == "" {
				atomic.AddInt64(&r.successCount, 1)
			} else {
				atomic.AddInt64(&r.errorCount, 1)
			}

			// Send result
			select {
			case results <- result:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

// executeProbe executes a single probe.
func (r *Runner) executeProbe(
	ctx context.Context,
	payload string,
	request *proto.ProbeBatchRequest,
) *proto.ProbeResult {
	result := &proto.ProbeResult{
		Payload:     payload,
		ProbeFamily: "generic",
	}

	// Build auth context
	auth := request.Headers

	// Execute injection
	responseBody, statusCode, latencyMs, err := r.adapter.Inject(payload, auth)

	result.ResponseBody = responseBody
	result.StatusCode = int32(statusCode)
	result.LatencyMs = latencyMs

	if err != nil {
		result.ErrorMessage = err.Error()
		return result
	}

	// Check for OOB callback if OOB server is configured
	if request.OobServer != "" {
		// Poll for callbacks (short timeout for batch processing)
		callbacks, _ := r.oobClient.PollCallbacks([]string{request.CampaignId}, 2)
		if len(callbacks) > 0 {
			result.OobCallback = true
			result.OobPayload = callbacks[0].RawData
		}
	}

	return result
}

// generateVariants generates all variants of a payload based on request flags.
func (r *Runner) generateVariants(payload string, request *proto.ProbeBatchRequest) []string {
	variants := []string{payload} // Always include original

	// Apply ChatInject
	if request.ApplyChatinject {
		wrapped := WrapPayload(payload, request.TemplateId)
		variants = append(variants, wrapped)
	}

	// Apply FlipAttack
	if request.ApplyFlipattack {
		flipVariants := ApplyAll(payload)
		variants = append(variants, flipVariants...)
	}

	// Apply Unicode injection (always applied for comprehensive testing)
	unicodeVariants := AllUnicodeVariants(payload)
	variants = append(variants, unicodeVariants...)

	return variants
}

// logStatistics logs throughput statistics every 10 seconds.
func (r *Runner) logStatistics(stop <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			elapsed := time.Since(r.startTime).Seconds()
			total := atomic.LoadInt64(&r.totalProbes)
			success := atomic.LoadInt64(&r.successCount)
			errors := atomic.LoadInt64(&r.errorCount)

			if total == 0 {
				continue
			}

			rps := float64(total) / elapsed
			successPct := float64(success) / float64(total) * 100
			errorPct := float64(errors) / float64(total) * 100

			log.Printf("[Runner] Stats: %.2f req/s, success=%.1f%%, errors=%.1f%%",
				rps, successPct, errorPct)

		case <-stop:
			return
		}
	}
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
