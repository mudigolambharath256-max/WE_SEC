package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// InjectionMode represents the type of HTTP injection.
type InjectionMode string

const (
	ModeJSON      InjectionMode = "json"
	ModeForm      InjectionMode = "form"
	ModeSSE       InjectionMode = "sse"
	ModeWebSocket InjectionMode = "websocket"
)

// Adapter provides a unified HTTP injection interface.
// Supports JSON body, form body, SSE, and WebSocket injection.
type Adapter struct {
	endpointURL  string
	method       string
	bodySchema   string // Template with $PAYLOAD placeholder
	headers      map[string]string
	mode         InjectionMode
	timeout      time.Duration
	proxyURL     string
}

// NewAdapter creates a new HTTP injection adapter.
//
// Args:
//   - endpointURL: Target endpoint URL
//   - method: HTTP method (GET, POST, etc.)
//   - bodySchema: Body template with $PAYLOAD placeholder (e.g., {"message":"$PAYLOAD"})
//   - headers: Additional HTTP headers
//
// Returns:
//   - *Adapter: Configured adapter instance
//
// The adapter automatically detects injection mode based on endpoint URL and headers.
func NewAdapter(endpointURL, method, bodySchema string, headers map[string]string) *Adapter {
	mode := detectMode(endpointURL, headers)

	// Read proxy configuration from environment
	proxyURL := os.Getenv("PROXY_BACKEND")
	if proxyURL != "" {
		proxyPort := os.Getenv("MITMPROXY_PORT")
		if proxyPort == "" {
			proxyPort = "8080"
		}
		proxyURL = fmt.Sprintf("http://localhost:%s", proxyPort)
	}

	adapter := &Adapter{
		endpointURL: endpointURL,
		method:      method,
		bodySchema:  bodySchema,
		headers:     headers,
		mode:        mode,
		timeout:     30 * time.Second,
		proxyURL:    proxyURL,
	}

	log.Printf("[Adapter] Initialized: mode=%s, endpoint=%s", mode, endpointURL)
	return adapter
}

// detectMode determines injection mode from URL and headers.
func detectMode(endpointURL string, headers map[string]string) InjectionMode {
	if strings.HasPrefix(endpointURL, "ws://") || strings.HasPrefix(endpointURL, "wss://") {
		return ModeWebSocket
	}

	for key, value := range headers {
		if strings.ToLower(key) == "accept" && strings.Contains(strings.ToLower(value), "text/event-stream") {
			return ModeSSE
		}
	}

	// Default to JSON for POST/PUT, form for others
	return ModeJSON
}

// Inject injects a payload into the target endpoint.
//
// Args:
//   - payload: The payload string to inject
//   - auth: Authentication context map
//
// Returns:
//   - responseBody: Response body as string
//   - statusCode: HTTP status code
//   - latencyMs: Request latency in milliseconds
//   - error: If injection fails
//
// All requests are logged at DEBUG level (not INFO to avoid noise).
func (a *Adapter) Inject(payload string, auth map[string]string) (string, int, int64, error) {
	startTime := time.Now()

	// Build request body from schema template
	body := strings.ReplaceAll(a.bodySchema, "$PAYLOAD", payload)

	// Merge auth headers with adapter headers
	allHeaders := make(map[string]string)
	for k, v := range a.headers {
		allHeaders[k] = v
	}
	authHeaders := BuildHeaders(auth)
	for k, v := range authHeaders {
		allHeaders[k] = v
	}

	var responseBody string
	var statusCode int
	var err error

	switch a.mode {
	case ModeJSON:
		responseBody, statusCode, err = a.injectJSON(body, allHeaders)
	case ModeForm:
		responseBody, statusCode, err = a.injectForm(payload, allHeaders)
	case ModeSSE:
		responseBody, statusCode, err = a.injectSSE(body, allHeaders)
	case ModeWebSocket:
		responseBody, statusCode, err = a.injectWebSocket(body, allHeaders)
	default:
		return "", 0, 0, fmt.Errorf("unsupported injection mode: %s", a.mode)
	}

	latencyMs := time.Since(startTime).Milliseconds()

	// Log at DEBUG level
	log.Printf("[Adapter] DEBUG: method=%s, url=%s, status=%d, latency=%dms, payload_len=%d, response_len=%d",
		a.method, a.endpointURL, statusCode, latencyMs, len(payload), len(responseBody))

	return responseBody, statusCode, latencyMs, err
}

// injectJSON performs JSON body injection.
func (a *Adapter) injectJSON(body string, headers map[string]string) (string, int, error) {
	req, err := http.NewRequest(a.method, a.endpointURL, bytes.NewBufferString(body))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Configure client with timeout and proxy
	client := &http.Client{
		Timeout: a.timeout,
	}

	if a.proxyURL != "" {
		proxyURLParsed, _ := url.Parse(a.proxyURL)
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURLParsed),
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return string(responseBody), resp.StatusCode, nil
}

// injectForm performs form body injection.
func (a *Adapter) injectForm(payload string, headers map[string]string) (string, int, error) {
	formData := url.Values{}
	formData.Set("message", payload)

	req, err := http.NewRequest(a.method, a.endpointURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: a.timeout}
	if a.proxyURL != "" {
		proxyURLParsed, _ := url.Parse(a.proxyURL)
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURLParsed),
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return string(responseBody), resp.StatusCode, nil
}

// injectSSE performs Server-Sent Events injection.
func (a *Adapter) injectSSE(body string, headers map[string]string) (string, int, error) {
	req, err := http.NewRequest(a.method, a.endpointURL, bytes.NewBufferString(body))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: a.timeout}
	if a.proxyURL != "" {
		proxyURLParsed, _ := url.Parse(a.proxyURL)
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURLParsed),
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read SSE stream until [DONE] or timeout
	var fullResponse strings.Builder
	reader := io.Reader(resp.Body)
	buf := make([]byte, 4096)

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				fullResponse.WriteString(chunk)
				if strings.Contains(chunk, "[DONE]") {
					close(done)
					return
				}
			}
			if err != nil {
				close(done)
				return
			}
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	return fullResponse.String(), resp.StatusCode, nil
}

// injectWebSocket performs WebSocket injection.
func (a *Adapter) injectWebSocket(body string, headers map[string]string) (string, int, error) {
	// WebSocket implementation using fasthttp
	// For simplicity, return placeholder implementation
	// Full WebSocket support would require gorilla/websocket or similar
	return "", 0, fmt.Errorf("WebSocket injection not yet implemented")
}
