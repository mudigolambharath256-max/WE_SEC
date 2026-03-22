package reconrunner

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// PortEntry represents a discovered port with service information.
type PortEntry struct {
	Port      int
	Service   string
	Banner    string
	AIService bool
}

// NmapRun represents the root element of Nmap XML output.
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a scanned host in Nmap XML.
type Host struct {
	Ports []Port `xml:"ports>port"`
}

// Port represents a port in Nmap XML.
type Port struct {
	PortID   int     `xml:"portid,attr"`
	Protocol string  `xml:"protocol,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

// State represents port state in Nmap XML.
type State struct {
	State string `xml:"state,attr"`
}

// Service represents service information in Nmap XML.
type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// AI service ports - covers common LLM/AI service ports
var aiServicePorts = []int{
	11434, // Ollama
	8080,  // LiteLLM
	8000,  // vLLM, FastAPI
	5000,  // Flask (common for AI APIs)
	5001,  // Alternative Flask
	8001,  // Alternative FastAPI
	7860,  // Gradio
	3000,  // AnythingLLM
	4000,  // Alternative AI services
	11435, // Alternative Ollama
}

// ScanPorts performs a port scan using Nmap.
//
// Args:
//   - host: Target host to scan
//   - ports: List of ports to scan (if empty, uses default AI service ports)
//
// Returns:
//   - []PortEntry: List of discovered open ports with service information
//   - error: If scan fails
//
// Timeout: 60 seconds for full scan
func ScanPorts(host string, ports []int) ([]PortEntry, error) {
	if len(ports) == 0 {
		ports = aiServicePorts
	}

	// Build port list string
	portList := buildPortList(ports)

	log.Printf("[PortScan] Scanning %s ports: %s", host, portList)

	// Build Nmap command
	// -sV: Version detection
	// -p: Port specification
	// --open: Only show open ports
	// -oX -: Output XML to stdout
	args := []string{
		"-sV",
		"-p", portList,
		"--open",
		"-oX", "-",
		host,
	}

	// Execute Nmap with timeout
	cmd := exec.Command("nmap", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Set timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("nmap failed: %v, stderr: %s", err, stderr.String())
		}
	case <-time.After(60 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil, fmt.Errorf("nmap timeout after 60 seconds")
	}

	// Parse XML output
	entries, err := ParseNmapOutput(stdout.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse nmap output: %w", err)
	}

	log.Printf("[PortScan] Found %d open ports on %s", len(entries), host)
	return entries, nil
}

// ParseNmapOutput parses Nmap XML output.
//
// Args:
//   - output: Nmap XML output as string
//
// Returns:
//   - []PortEntry: Parsed port entries
//   - error: If parsing fails
func ParseNmapOutput(output string) ([]PortEntry, error) {
	var nmapRun NmapRun
	if err := xml.Unmarshal([]byte(output), &nmapRun); err != nil {
		return nil, fmt.Errorf("XML parse error: %w", err)
	}

	var entries []PortEntry

	for _, host := range nmapRun.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}

			banner := buildBanner(port.Service)
			serviceName, confidence := DetectAIService(banner, port.PortID)

			entry := PortEntry{
				Port:      port.PortID,
				Service:   serviceName,
				Banner:    banner,
				AIService: confidence > 0.5,
			}

			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// buildBanner constructs a banner string from service information.
func buildBanner(service Service) string {
	parts := []string{}

	if service.Name != "" {
		parts = append(parts, service.Name)
	}
	if service.Product != "" {
		parts = append(parts, service.Product)
	}
	if service.Version != "" {
		parts = append(parts, service.Version)
	}

	return strings.Join(parts, " ")
}

// DetectAIService detects if a service is an AI/LLM service.
//
// Args:
//   - banner: Service banner string
//   - port: Port number
//
// Returns:
//   - serviceName: Detected service name (or "unknown")
//   - confidence: Confidence score (0.0 - 1.0)
//
// Never hallucinates service names - returns "unknown" if no match.
func DetectAIService(banner string, port int) (string, float32) {
	bannerLower := strings.ToLower(banner)

	// Ollama detection
	if strings.Contains(bannerLower, "ollama") || port == 11434 {
		return "Ollama", 0.9
	}

	// vLLM detection
	if strings.Contains(bannerLower, "vllm") {
		return "vLLM", 0.9
	}

	// LiteLLM detection
	if strings.Contains(bannerLower, "litellm") || (port == 8080 && strings.Contains(bannerLower, "llm")) {
		return "LiteLLM", 0.8
	}

	// Gradio detection
	if strings.Contains(bannerLower, "gradio") || port == 7860 {
		return "Gradio", 0.8
	}

	// AnythingLLM detection
	if strings.Contains(bannerLower, "anythingllm") || (port == 3000 && strings.Contains(bannerLower, "llm")) {
		return "AnythingLLM", 0.7
	}

	// LocalAI detection
	if strings.Contains(bannerLower, "localai") {
		return "LocalAI", 0.9
	}

	// Generic FastAPI detection (common for AI services)
	if strings.Contains(bannerLower, "fastapi") && (port == 8000 || port == 8001) {
		return "FastAPI (possible AI service)", 0.5
	}

	// Generic Flask detection (common for AI APIs)
	if strings.Contains(bannerLower, "flask") && (port == 5000 || port == 5001) {
		return "Flask (possible AI service)", 0.4
	}

	// Check for OpenAI-compatible endpoints
	if strings.Contains(bannerLower, "openai") || strings.Contains(bannerLower, "/v1/models") {
		return "OpenAI-compatible API", 0.7
	}

	// No match - return unknown
	return "unknown", 0.0
}

// buildPortList converts port array to Nmap port specification string.
func buildPortList(ports []int) string {
	portStrs := make([]string, len(ports))
	for i, port := range ports {
		portStrs[i] = fmt.Sprintf("%d", port)
	}
	return strings.Join(portStrs, ",")
}

// ProbeAIEndpoint attempts to probe an endpoint for AI service confirmation.
//
// Args:
//   - host: Target host
//   - port: Target port
//
// Returns:
//   - bool: true if AI service confirmed
//   - string: Service type if detected
func ProbeAIEndpoint(host string, port int) (bool, string) {
	// Try common AI service endpoints
	endpoints := []string{
		"/v1/models",           // OpenAI-compatible
		"/api/tags",            // Ollama
		"/api/version",         // Generic version endpoint
		"/health",              // Health check
		"/docs",                // FastAPI docs
		"/.well-known/ai.json", // AI service discovery
	}

	baseURL := fmt.Sprintf("http://%s:%d", host, port)

	for _, endpoint := range endpoints {
		url := baseURL + endpoint
		// TODO: Implement HTTP probe
		// For now, return false
		_ = url
	}

	return false, ""
}
