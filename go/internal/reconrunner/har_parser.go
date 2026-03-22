package reconrunner

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// HARFile represents the root structure of a HAR file.
type HARFile struct {
	Log HARLog `json:"log"`
}

// HARLog represents the log section of a HAR file.
type HARLog struct {
	Entries []HAREntry `json:"entries"`
}

// HAREntry represents a single HTTP request/response in HAR.
type HAREntry struct {
	Request  HARRequest  `json:"request"`
	Response HARResponse `json:"response"`
}

// HARRequest represents an HTTP request in HAR.
type HARRequest struct {
	Method  string       `json:"method"`
	URL     string       `json:"url"`
	Headers []HARHeader  `json:"headers"`
	Cookies []HARCookie  `json:"cookies"`
}

// HARResponse represents an HTTP response in HAR.
type HARResponse struct {
	Status  int         `json:"status"`
	Headers []HARHeader `json:"headers"`
}

// HARHeader represents an HTTP header.
type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARCookie represents an HTTP cookie.
type HARCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// EndpointMap represents discovered endpoints and authentication info.
type EndpointMap struct {
	Endpoints []EndpointEntry
	AuthType  string
}

// ParseHAR parses a HAR file and extracts endpoint information.
//
// Args:
//   - harData: HAR file content as bytes
//
// Returns:
//   - EndpointMap: Discovered endpoints and authentication type
//   - error: If parsing fails
//
// This is useful for importing browser traffic captures into the testing framework.
func ParseHAR(harData []byte) (EndpointMap, error) {
	var harFile HARFile
	if err := json.Unmarshal(harData, &harFile); err != nil {
		return EndpointMap{}, fmt.Errorf("failed to parse HAR: %w", err)
	}

	endpointMap := EndpointMap{
		Endpoints: []EndpointEntry{},
		AuthType:  "unknown",
	}

	// Track unique endpoints
	seen := make(map[string]bool)

	// Extract endpoints from entries
	for _, entry := range harFile.Log.Entries {
		url := entry.Request.URL

		// Skip if already seen
		if seen[url] {
			continue
		}
		seen[url] = true

		// Create endpoint entry
		endpoint := EndpointEntry{
			URL:    url,
			Status: entry.Response.Status,
			Size:   0, // HAR doesn't always include size
		}

		endpointMap.Endpoints = append(endpointMap.Endpoints, endpoint)

		// Detect authentication type from first request
		if endpointMap.AuthType == "unknown" {
			authType := detectAuthType(entry.Request)
			if authType != "unknown" {
				endpointMap.AuthType = authType
				log.Printf("[HARParser] Detected auth type: %s", authType)
			}
		}
	}

	log.Printf("[HARParser] Parsed HAR: %d unique endpoints, auth=%s",
		len(endpointMap.Endpoints), endpointMap.AuthType)

	return endpointMap, nil
}

// detectAuthType detects authentication type from request headers.
func detectAuthType(request HARRequest) string {
	for _, header := range request.Headers {
		headerName := strings.ToLower(header.Name)
		headerValue := strings.ToLower(header.Value)

		// Check for Authorization header
		if headerName == "authorization" {
			if strings.HasPrefix(headerValue, "bearer ") {
				// Check if it's a JWT
				if isJWT(header.Value) {
					return "jwt"
				}
				return "oauth_bearer"
			}
			if strings.HasPrefix(headerValue, "basic ") {
				return "basic"
			}
			// Generic API key in Authorization header
			return "api_key"
		}

		// Check for API key headers
		if strings.Contains(headerName, "api-key") ||
			strings.Contains(headerName, "apikey") ||
			strings.Contains(headerName, "x-api-key") {
			return "api_key"
		}
	}

	// Check for session cookies
	for _, cookie := range request.Cookies {
		cookieName := strings.ToLower(cookie.Name)
		if strings.Contains(cookieName, "session") ||
			strings.Contains(cookieName, "sid") ||
			cookieName == "connect.sid" ||
			cookieName == "sessionid" {
			return "session_cookie"
		}
	}

	return "unknown"
}

// isJWT checks if a token is a JWT (has 3 parts separated by dots).
func isJWT(token string) bool {
	// Remove "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")

	parts := strings.Split(token, ".")
	return len(parts) == 3
}

// FilterAIEndpoints filters endpoints that are likely AI/LLM related.
//
// Args:
//   - endpoints: List of all endpoints
//
// Returns:
//   - []EndpointEntry: Filtered list of AI-related endpoints
func FilterAIEndpoints(endpoints []EndpointEntry) []EndpointEntry {
	var aiEndpoints []EndpointEntry

	aiKeywords := []string{
		"/chat",
		"/completion",
		"/generate",
		"/inference",
		"/predict",
		"/model",
		"/embedding",
		"/v1/",
		"/api/chat",
		"/api/completion",
		"/api/generate",
		"ollama",
		"llm",
		"gpt",
		"claude",
	}

	for _, endpoint := range endpoints {
		urlLower := strings.ToLower(endpoint.URL)

		for _, keyword := range aiKeywords {
			if strings.Contains(urlLower, keyword) {
				aiEndpoints = append(aiEndpoints, endpoint)
				break
			}
		}
	}

	log.Printf("[HARParser] Filtered %d AI endpoints from %d total",
		len(aiEndpoints), len(endpoints))

	return aiEndpoints
}

// ExtractAuthTokens extracts authentication tokens from HAR entries.
//
// Args:
//   - harData: HAR file content as bytes
//
// Returns:
//   - map[string]string: Map of auth type to token value
//   - error: If parsing fails
func ExtractAuthTokens(harData []byte) (map[string]string, error) {
	var harFile HARFile
	if err := json.Unmarshal(harData, &harFile); err != nil {
		return nil, fmt.Errorf("failed to parse HAR: %w", err)
	}

	tokens := make(map[string]string)

	for _, entry := range harFile.Log.Entries {
		// Extract from Authorization header
		for _, header := range entry.Request.Headers {
			if strings.ToLower(header.Name) == "authorization" {
				tokens["authorization"] = header.Value
				break
			}
		}

		// Extract from API key headers
		for _, header := range entry.Request.Headers {
			headerName := strings.ToLower(header.Name)
			if strings.Contains(headerName, "api-key") ||
				strings.Contains(headerName, "apikey") {
				tokens["api_key"] = header.Value
				break
			}
		}

		// Extract session cookies
		for _, cookie := range entry.Request.Cookies {
			cookieName := strings.ToLower(cookie.Name)
			if strings.Contains(cookieName, "session") {
				tokens["session_cookie"] = fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
				break
			}
		}
	}

	return tokens, nil
}
