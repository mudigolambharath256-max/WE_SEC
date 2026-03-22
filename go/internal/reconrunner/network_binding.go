package reconrunner

import (
	"fmt"
	"log"
	"net"
	"time"
)

// BindingResult represents network binding check result.
type BindingResult struct {
	Exposed      bool
	BoundAddress string
}

// CheckBinding checks if a port is exposed externally or bound to localhost.
//
// Args:
//   - host: Target host
//   - port: Target port
//
// Returns:
//   - BindingResult: Binding information
//   - error: If check fails
//
// This is critical for detecting misconfigured services that should be
// localhost-only but are exposed to the network.
func CheckBinding(host string, port int) (BindingResult, error) {
	result := BindingResult{}

	// Try to connect to the port
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return result, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Get local and remote addresses
	localAddr := conn.LocalAddr().String()
	remoteAddr := conn.RemoteAddr().String()

	result.BoundAddress = remoteAddr

	// Check if bound to localhost
	if isLocalhost(host) {
		result.Exposed = false
		log.Printf("[NetworkBinding] %s:%d is localhost-bound (safe)", host, port)
	} else {
		result.Exposed = true
		log.Printf("[NetworkBinding] WARNING: %s:%d is externally exposed", host, port)
	}

	log.Printf("[NetworkBinding] Connection: local=%s, remote=%s", localAddr, remoteAddr)

	return result, nil
}

// isLocalhost checks if a host is localhost.
func isLocalhost(host string) bool {
	localhostAddrs := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0", // Binds to all interfaces but may be intended as localhost
	}

	for _, addr := range localhostAddrs {
		if host == addr {
			return true
		}
	}

	return false
}

// CheckMultipleBindings checks bindings for multiple ports.
//
// Args:
//   - host: Target host
//   - ports: List of ports to check
//
// Returns:
//   - map[int]BindingResult: Map of port to binding result
//   - error: If any check fails critically
func CheckMultipleBindings(host string, ports []int) (map[int]BindingResult, error) {
	results := make(map[int]BindingResult)

	for _, port := range ports {
		result, err := CheckBinding(host, port)
		if err != nil {
			log.Printf("[NetworkBinding] Failed to check port %d: %v", port, err)
			continue
		}
		results[port] = result
	}

	return results, nil
}

// DetectMisconfiguredServices detects services that should be localhost-only.
//
// Args:
//   - host: Target host
//   - ports: List of discovered open ports
//
// Returns:
//   - []int: List of misconfigured ports (exposed when they should be localhost)
func DetectMisconfiguredServices(host string, ports []int) []int {
	var misconfigured []int

	// Ports that should typically be localhost-only
	localhostOnlyPorts := map[int]string{
		5432:  "PostgreSQL",
		3306:  "MySQL",
		6379:  "Redis",
		27017: "MongoDB",
		9200:  "Elasticsearch",
		5672:  "RabbitMQ",
		11211: "Memcached",
	}

	for _, port := range ports {
		if serviceName, shouldBeLocal := localhostOnlyPorts[port]; shouldBeLocal {
			result, err := CheckBinding(host, port)
			if err != nil {
				continue
			}

			if result.Exposed && !isLocalhost(host) {
				log.Printf("[NetworkBinding] CRITICAL: %s (port %d) is exposed externally",
					serviceName, port)
				misconfigured = append(misconfigured, port)
			}
		}
	}

	return misconfigured
}

// GetBindingRecommendation provides security recommendations for binding.
//
// Args:
//   - port: Port number
//   - exposed: Whether the port is exposed
//
// Returns:
//   - string: Security recommendation
func GetBindingRecommendation(port int, exposed bool) string {
	if !exposed {
		return "Service is properly bound to localhost. No action needed."
	}

	// Check if this is a port that should be localhost-only
	localhostOnlyPorts := map[int]string{
		5432:  "PostgreSQL",
		3306:  "MySQL",
		6379:  "Redis",
		27017: "MongoDB",
		9200:  "Elasticsearch",
		5672:  "RabbitMQ",
		11211: "Memcached",
		11434: "Ollama (if not intended for network access)",
	}

	if serviceName, shouldBeLocal := localhostOnlyPorts[port]; shouldBeLocal {
		return fmt.Sprintf(
			"CRITICAL: %s should be bound to localhost only. "+
				"Configure the service to bind to 127.0.0.1 instead of 0.0.0.0. "+
				"Exposing this service to the network creates a security risk.",
			serviceName,
		)
	}

	return fmt.Sprintf(
		"Port %d is exposed to the network. "+
			"Ensure this is intentional and proper authentication is configured.",
		port,
	)
}
