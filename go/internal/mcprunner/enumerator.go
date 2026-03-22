package mcprunner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// MCPTool represents an MCP tool definition.
type MCPTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema string `json:"inputSchema"`
}

// MCPResource represents an MCP resource.
type MCPResource struct {
	URI      string `json:"uri"`
	Name     string `json:"name"`
	MimeType string `json:"mimeType"`
}

// MCPPrompt represents an MCP prompt template.
type MCPPrompt struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// MCPSchema represents the complete MCP server schema.
type MCPSchema struct {
	Tools            []MCPTool
	Resources        []MCPResource
	Prompts          []MCPPrompt
	SamplingEnabled  bool
	Transport        string
}

// Enumerator handles MCP JSON-RPC 2.0 communication.
type Enumerator struct {
	serverURL string
	auth      map[string]string
	client    *http.Client
	requestID int64
}

// NewEnumerator creates a new MCP enumerator.
//
// Args:
//   - serverURL: MCP server URL
//   - auth: Authentication context
//
// Returns:
//   - *Enumerator: Configured enumerator instance
func NewEnumerator(serverURL string, auth map[string]string) *Enumerator {
	return &Enumerator{
		serverURL: serverURL,
		auth:      auth,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		requestID: 0,
	}
}

// Initialize sends the MCP initialize request.
//
// Args: None
//
// Returns:
//   - error: If initialization fails
//
// Sends: {"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}
func (e *Enumerator) Initialize() error {
	requestID := atomic.AddInt64(&e.requestID, 1)

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"roots": map[string]interface{}{
					"listChanged": true,
				},
				"sampling": map[string]interface{}{},
			},
			"clientInfo": map[string]interface{}{
				"name":    "llmrt",
				"version": "1.0.0",
			},
		},
	}

	response, err := e.sendRequest(request)
	if err != nil {
		return fmt.Errorf("initialize failed: %w", err)
	}

	log.Printf("[MCP] Initialized: %s", e.serverURL)
	log.Printf("[MCP] DEBUG: Initialize response: %s", string(response))

	return nil
}

// ListTools retrieves all available tools from the MCP server.
//
// Returns:
//   - []MCPTool: List of available tools
//   - error: If request fails
//
// Sends: {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
func (e *Enumerator) ListTools() ([]MCPTool, error) {
	requestID := atomic.AddInt64(&e.requestID, 1)

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}

	responseData, err := e.sendRequest(request)
	if err != nil {
		return nil, fmt.Errorf("tools/list failed: %w", err)
	}

	// Parse response
	var response struct {
		Result struct {
			Tools []struct {
				Name        string                 `json:"name"`
				Description string                 `json:"description"`
				InputSchema map[string]interface{} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}

	if err := json.Unmarshal(responseData, &response); err != nil {
		return nil, fmt.Errorf("failed to parse tools response: %w", err)
	}

	// Convert to MCPTool
	tools := make([]MCPTool, len(response.Result.Tools))
	for i, tool := range response.Result.Tools {
		schemaJSON, _ := json.Marshal(tool.InputSchema)
		tools[i] = MCPTool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: string(schemaJSON),
		}
	}

	log.Printf("[MCP] Listed %d tools", len(tools))
	return tools, nil
}

// ListResources retrieves all available resources from the MCP server.
//
// Returns:
//   - []MCPResource: List of available resources
//   - error: If request fails
func (e *Enumerator) ListResources() ([]MCPResource, error) {
	requestID := atomic.AddInt64(&e.requestID, 1)

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "resources/list",
		"params":  map[string]interface{}{},
	}

	responseData, err := e.sendRequest(request)
	if err != nil {
		return nil, fmt.Errorf("resources/list failed: %w", err)
	}

	// Parse response
	var response struct {
		Result struct {
			Resources []struct {
				URI      string `json:"uri"`
				Name     string `json:"name"`
				MimeType string `json:"mimeType"`
			} `json:"resources"`
		} `json:"result"`
	}

	if err := json.Unmarshal(responseData, &response); err != nil {
		return nil, fmt.Errorf("failed to parse resources response: %w", err)
	}

	// Convert to MCPResource
	resources := make([]MCPResource, len(response.Result.Resources))
	for i, res := range response.Result.Resources {
		resources[i] = MCPResource{
			URI:      res.URI,
			Name:     res.Name,
			MimeType: res.MimeType,
		}
	}

	log.Printf("[MCP] Listed %d resources", len(resources))
	return resources, nil
}

// ListPrompts retrieves all available prompts from the MCP server.
//
// Returns:
//   - []MCPPrompt: List of available prompts
//   - error: If request fails
func (e *Enumerator) ListPrompts() ([]MCPPrompt, error) {
	requestID := atomic.AddInt64(&e.requestID, 1)

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "prompts/list",
		"params":  map[string]interface{}{},
	}

	responseData, err := e.sendRequest(request)
	if err != nil {
		return nil, fmt.Errorf("prompts/list failed: %w", err)
	}

	// Parse response
	var response struct {
		Result struct {
			Prompts []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"prompts"`
		} `json:"result"`
	}

	if err := json.Unmarshal(responseData, &response); err != nil {
		return nil, fmt.Errorf("failed to parse prompts response: %w", err)
	}

	// Convert to MCPPrompt
	prompts := make([]MCPPrompt, len(response.Result.Prompts))
	for i, prompt := range response.Result.Prompts {
		prompts[i] = MCPPrompt{
			Name:        prompt.Name,
			Description: prompt.Description,
		}
	}

	log.Printf("[MCP] Listed %d prompts", len(prompts))
	return prompts, nil
}

// CallTool invokes an MCP tool with arguments.
//
// Args:
//   - name: Tool name
//   - args: Tool arguments as map
//
// Returns:
//   - string: Tool response
//   - error: If call fails
//
// Sends: {"jsonrpc":"2.0","id":N,"method":"tools/call","params":{"name":N,"arguments":args}}
func (e *Enumerator) CallTool(name string, args map[string]interface{}) (string, error) {
	requestID := atomic.AddInt64(&e.requestID, 1)

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      name,
			"arguments": args,
		},
	}

	responseData, err := e.sendRequest(request)
	if err != nil {
		return "", fmt.Errorf("tools/call failed: %w", err)
	}

	log.Printf("[MCP] DEBUG: Tool call response: %s", string(responseData))
	return string(responseData), nil
}

// sendRequest sends a JSON-RPC request to the MCP server.
func (e *Enumerator) sendRequest(request map[string]interface{}) ([]byte, error) {
	// Marshal request
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	log.Printf("[MCP] DEBUG: Request: %s", string(requestBody))

	// Create HTTP request
	req, err := http.NewRequest("POST", e.serverURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Add authentication headers
	for key, value := range e.auth {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for JSON-RPC error
	var jsonRPCResponse struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(responseBody, &jsonRPCResponse); err == nil {
		if jsonRPCResponse.Error != nil {
			return nil, fmt.Errorf("JSON-RPC error %d: %s",
				jsonRPCResponse.Error.Code,
				jsonRPCResponse.Error.Message)
		}
	}

	return responseBody, nil
}

// EnumerateAll enumerates all MCP capabilities.
//
// Returns:
//   - MCPSchema: Complete schema with tools, resources, and prompts
//   - error: If enumeration fails
func (e *Enumerator) EnumerateAll() (MCPSchema, error) {
	schema := MCPSchema{
		Transport: "http",
	}

	// Initialize
	if err := e.Initialize(); err != nil {
		return schema, fmt.Errorf("initialization failed: %w", err)
	}

	// List tools
	tools, err := e.ListTools()
	if err != nil {
		log.Printf("[MCP] Warning: Failed to list tools: %v", err)
	} else {
		schema.Tools = tools
	}

	// List resources
	resources, err := e.ListResources()
	if err != nil {
		log.Printf("[MCP] Warning: Failed to list resources: %v", err)
	} else {
		schema.Resources = resources
	}

	// List prompts
	prompts, err := e.ListPrompts()
	if err != nil {
		log.Printf("[MCP] Warning: Failed to list prompts: %v", err)
	} else {
		schema.Prompts = prompts
	}

	// Check for sampling capability
	schema.SamplingEnabled = e.checkSamplingCapability()

	log.Printf("[MCP] Enumeration complete: %d tools, %d resources, %d prompts",
		len(schema.Tools), len(schema.Resources), len(schema.Prompts))

	return schema, nil
}

// checkSamplingCapability checks if the server supports sampling.
func (e *Enumerator) checkSamplingCapability() bool {
	// Try to call sampling/createMessage
	requestID := atomic.AddInt64(&e.requestID, 1)

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "sampling/createMessage",
		"params": map[string]interface{}{
			"messages": []map[string]interface{}{
				{
					"role":    "user",
					"content": map[string]interface{}{"type": "text", "text": "test"},
				},
			},
			"maxTokens": 1,
		},
	}

	_, err := e.sendRequest(request)
	return err == nil
}

// DetectTransport detects the MCP transport type from URL.
func DetectTransport(serverURL string) string {
	if strings.HasPrefix(serverURL, "http://") || strings.HasPrefix(serverURL, "https://") {
		return "http"
	}
	if strings.HasPrefix(serverURL, "ws://") || strings.HasPrefix(serverURL, "wss://") {
		return "sse"
	}
	return "stdio"
}
