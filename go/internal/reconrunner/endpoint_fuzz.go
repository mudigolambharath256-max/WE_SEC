package reconrunner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// EndpointEntry represents a discovered endpoint.
type EndpointEntry struct {
	URL    string
	Status int
	Size   int64
}

// FuzzEndpoints performs endpoint fuzzing/discovery.
//
// Args:
//   - baseURL: Base URL to fuzz (e.g., http://example.com)
//   - wordlist: Path to wordlist file or built-in wordlist name
//   - concurrency: Number of concurrent requests
//   - delayMs: Delay between requests in milliseconds
//
// Returns:
//   - []EndpointEntry: List of discovered endpoints
//   - error: If fuzzing fails
func FuzzEndpoints(baseURL, wordlist string, concurrency, delayMs int) ([]EndpointEntry, error) {
	// Load wordlist
	words, err := loadWordlist(wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	log.Printf("[EndpointFuzz] Starting fuzzing: base=%s, words=%d, concurrency=%d",
		baseURL, len(words), concurrency)

	// Create HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Create worker pool
	ctx := context.Background()
	wordChan := make(chan string, len(words))
	resultChan := make(chan EndpointEntry, len(words))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fuzzWorker(ctx, client, baseURL, wordChan, resultChan, delayMs)
		}()
	}

	// Feed words to workers
	for _, word := range words {
		wordChan <- word
	}
	close(wordChan)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var entries []EndpointEntry
	for entry := range resultChan {
		entries = append(entries, entry)
	}

	log.Printf("[EndpointFuzz] Fuzzing complete: %d endpoints discovered", len(entries))
	return entries, nil
}

// fuzzWorker is a worker goroutine that fuzzes endpoints.
func fuzzWorker(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	words <-chan string,
	results chan<- EndpointEntry,
	delayMs int,
) {
	for word := range words {
		// Build URL
		url := fmt.Sprintf("%s/%s", baseURL, word)

		// Make request
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			// Skip failed requests
			continue
		}

		// Check if endpoint exists (200-299, 401, 403)
		if (resp.StatusCode >= 200 && resp.StatusCode < 300) ||
			resp.StatusCode == 401 ||
			resp.StatusCode == 403 {

			entry := EndpointEntry{
				URL:    url,
				Status: resp.StatusCode,
				Size:   resp.ContentLength,
			}
			results <- entry

			log.Printf("[EndpointFuzz] Found: %s [%d]", url, resp.StatusCode)
		}

		resp.Body.Close()

		// Rate limiting delay
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}
}

// loadWordlist loads a wordlist from file or returns built-in wordlist.
func loadWordlist(wordlist string) ([]string, error) {
	// Check if it's a built-in wordlist
	if wordlist == "ai-endpoints" {
		return getAIEndpointsWordlist(), nil
	}

	// TODO: Load from file
	// For now, return built-in wordlist
	return getAIEndpointsWordlist(), nil
}

// getAIEndpointsWordlist returns a built-in wordlist for AI service endpoints.
func getAIEndpointsWordlist() []string {
	return []string{
		// OpenAI-compatible
		"v1/models",
		"v1/chat/completions",
		"v1/completions",
		"v1/embeddings",

		// Ollama
		"api/tags",
		"api/generate",
		"api/chat",
		"api/embeddings",
		"api/pull",
		"api/push",

		// LiteLLM
		"health",
		"models",
		"model/info",

		// Generic AI endpoints
		"api/chat",
		"api/completion",
		"api/generate",
		"api/inference",
		"api/predict",
		"chat",
		"completion",
		"generate",
		"inference",
		"predict",

		// Admin/config endpoints
		"admin",
		"config",
		"settings",
		"api/config",
		"api/settings",

		// Documentation
		"docs",
		"api/docs",
		"swagger",
		"openapi.json",
		"api.json",

		// Health/status
		"health",
		"status",
		"ping",
		"version",
		"api/health",
		"api/status",

		// MCP endpoints
		"mcp",
		"api/mcp",
		".well-known/mcp.json",
		"mcp/tools",
		"mcp/resources",

		// RAG endpoints
		"api/documents",
		"api/upload",
		"api/search",
		"documents",
		"upload",
		"search",

		// Authentication
		"auth",
		"login",
		"api/auth",
		"api/login",
		"api/token",

		// Gradio
		"api/predict",
		"api/queue",
		"api/",

		// Jupyter/Notebook
		"api/kernels",
		"api/sessions",
		"notebooks",
	}
}
