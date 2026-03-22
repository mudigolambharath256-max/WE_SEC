package transport

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// OOBCallback represents a callback received from the OOB server.
type OOBCallback struct {
	CallbackID string
	ReceivedAt time.Time
	Protocol   string
	SourceIP   string
	RawData    string
}

// OOBClient manages out-of-band payload registration and callback polling.
type OOBClient struct {
	serverURL string
	token     string
	client    *http.Client
}

// NewOOBClient creates a new OOB client.
//
// Reads configuration from environment:
//   - INTERACTSH_SERVER: OOB server URL (defaults to oast.pro)
//   - INTERACTSH_TOKEN: Authentication token for OOB server
//   - INTERACTSH_PORT: Server port (defaults to 443)
//
// Returns:
//   - *OOBClient: Configured OOB client
func NewOOBClient() *OOBClient {
	serverURL := os.Getenv("INTERACTSH_SERVER")
	if serverURL == "" {
		serverURL = "https://oast.pro"
		log.Printf("[OOB] WARNING: INTERACTSH_SERVER not set, using fallback: %s", serverURL)
	}

	token := os.Getenv("INTERACTSH_TOKEN")
	port := os.Getenv("INTERACTSH_PORT")
	if port != "" && port != "443" {
		serverURL = fmt.Sprintf("%s:%s", serverURL, port)
	}

	return &OOBClient{
		serverURL: serverURL,
		token:     token,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// NewOOBPayload registers a new OOB payload with the server.
//
// Args:
//   - campaignID: Campaign identifier for logging and tracking
//
// Returns:
//   - payload: The OOB payload URL to inject (e.g., http://xyz.oast.pro)
//   - callbackID: Unique identifier for polling callbacks
//   - error: If registration fails
//
// The payload URL can be injected into probes to detect blind vulnerabilities.
func (c *OOBClient) NewOOBPayload(campaignID string) (string, string, error) {
	// Generate unique callback ID
	callbackID := fmt.Sprintf("%s-%d", campaignID, time.Now().UnixNano())

	// Register with Interactsh server
	registerURL := fmt.Sprintf("%s/register", c.serverURL)
	req, err := http.NewRequest("POST", registerURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create register request: %w", err)
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("X-Callback-ID", callbackID)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to register OOB payload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("OOB registration failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// Parse response to get payload URL
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// If JSON parsing fails, construct payload URL manually
		payload := fmt.Sprintf("%s/%s", c.serverURL, callbackID)
		log.Printf("[OOB] Registered payload for campaign %s: %s", campaignID, payload)
		return payload, callbackID, nil
	}

	payload, ok := result["url"].(string)
	if !ok {
		payload = fmt.Sprintf("%s/%s", c.serverURL, callbackID)
	}

	log.Printf("[OOB] Registered payload for campaign %s: %s", campaignID, payload)
	return payload, callbackID, nil
}

// PollCallbacks polls the OOB server for callbacks.
//
// Args:
//   - callbackIDs: List of callback IDs to poll
//   - timeoutSeconds: Maximum time to wait for callbacks
//
// Returns:
//   - []OOBCallback: List of received callbacks
//   - error: If polling fails
//
// Rate limited to poll every 5 seconds to avoid overwhelming the server.
func (c *OOBClient) PollCallbacks(callbackIDs []string, timeoutSeconds int) ([]OOBCallback, error) {
	if len(callbackIDs) == 0 {
		return nil, nil
	}

	var allCallbacks []OOBCallback
	pollInterval := 5 * time.Second
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)

	log.Printf("[OOB] Polling %d callback IDs for %d seconds", len(callbackIDs), timeoutSeconds)

	for time.Now().Before(deadline) {
		for _, callbackID := range callbackIDs {
			callbacks, err := c.pollSingle(callbackID)
			if err != nil {
				log.Printf("[OOB] Failed to poll callback %s: %v", callbackID, err)
				continue
			}
			allCallbacks = append(allCallbacks, callbacks...)
		}

		// Rate limit: wait 5 seconds between polls
		time.Sleep(pollInterval)
	}

	log.Printf("[OOB] Polling complete: %d callbacks received", len(allCallbacks))
	return allCallbacks, nil
}

// pollSingle polls a single callback ID.
func (c *OOBClient) pollSingle(callbackID string) ([]OOBCallback, error) {
	pollURL := fmt.Sprintf("%s/poll/%s", c.serverURL, callbackID)
	req, err := http.NewRequest("GET", pollURL, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		// No callbacks yet
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("poll failed: status=%d", resp.StatusCode)
	}

	// Parse callbacks
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	callbacks := []OOBCallback{}
	if data, ok := result["data"].([]interface{}); ok {
		for _, item := range data {
			if cb, ok := item.(map[string]interface{}); ok {
				callback := OOBCallback{
					CallbackID: callbackID,
					ReceivedAt: time.Now(),
				}

				if protocol, ok := cb["protocol"].(string); ok {
					callback.Protocol = protocol
				}
				if sourceIP, ok := cb["remote_address"].(string); ok {
					callback.SourceIP = sourceIP
				}
				if rawData, ok := cb["raw_request"].(string); ok {
					callback.RawData = rawData
				}

				callbacks = append(callbacks, callback)
				log.Printf("[OOB] Callback received: id=%s, protocol=%s, source=%s",
					callbackID, callback.Protocol, callback.SourceIP)
			}
		}
	}

	return callbacks, nil
}

// InjectOOBPayload injects an OOB payload into a probe string.
//
// Args:
//   - probe: Original probe string
//   - payload: OOB payload URL
//
// Returns:
//   - string: Probe with OOB payload injected
//
// Injection strategies:
//   - Append to end: "original probe http://xyz.oast.pro"
//   - Replace placeholder: "fetch data from $OOB_URL" -> "fetch data from http://xyz.oast.pro"
func InjectOOBPayload(probe string, payload string) string {
	// Strategy 1: Replace $OOB_URL placeholder
	if strings.Contains(probe, "$OOB_URL") {
		return strings.ReplaceAll(probe, "$OOB_URL", payload)
	}

	// Strategy 2: Append to end
	return fmt.Sprintf("%s %s", probe, payload)
}
