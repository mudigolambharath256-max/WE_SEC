package proberunner

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadCorpus loads a payload corpus from a text file.
//
// Args:
//   - path: Path to corpus file (one payload per line)
//
// Returns:
//   - []string: List of payloads
//   - error: If file cannot be read
//
// Empty lines and lines starting with # are skipped.
func LoadCorpus(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open corpus file: %w", err)
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		payloads = append(payloads, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading corpus file: %w", err)
	}

	return payloads, nil
}

// LoadMultipleCorpora loads payloads from multiple corpus files.
//
// Args:
//   - paths: List of corpus file paths
//
// Returns:
//   - []string: Combined list of payloads from all files
//   - error: If any file cannot be read
func LoadMultipleCorpora(paths []string) ([]string, error) {
	var allPayloads []string

	for _, path := range paths {
		payloads, err := LoadCorpus(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load corpus %s: %w", path, err)
		}
		allPayloads = append(allPayloads, payloads...)
	}

	return allPayloads, nil
}

// SaveCorpus saves payloads to a corpus file.
//
// Args:
//   - path: Output file path
//   - payloads: List of payloads to save
//
// Returns:
//   - error: If file cannot be written
func SaveCorpus(path string, payloads []string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create corpus file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, payload := range payloads {
		if _, err := writer.WriteString(payload + "\n"); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return nil
}

// DeduplicatePayloads removes duplicate payloads from a list.
//
// Args:
//   - payloads: List of payloads (may contain duplicates)
//
// Returns:
//   - []string: Deduplicated list of payloads
func DeduplicatePayloads(payloads []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, payload := range payloads {
		if !seen[payload] {
			seen[payload] = true
			unique = append(unique, payload)
		}
	}

	return unique
}

// FilterPayloadsByLength filters payloads by length constraints.
//
// Args:
//   - payloads: List of payloads
//   - minLength: Minimum payload length (inclusive)
//   - maxLength: Maximum payload length (inclusive, 0 = no limit)
//
// Returns:
//   - []string: Filtered list of payloads
func FilterPayloadsByLength(payloads []string, minLength, maxLength int) []string {
	var filtered []string

	for _, payload := range payloads {
		length := len(payload)
		if length < minLength {
			continue
		}
		if maxLength > 0 && length > maxLength {
			continue
		}
		filtered = append(filtered, payload)
	}

	return filtered
}

// SamplePayloads randomly samples N payloads from a list.
//
// Args:
//   - payloads: List of payloads
//   - n: Number of payloads to sample
//
// Returns:
//   - []string: Sampled payloads (may be less than n if input is smaller)
func SamplePayloads(payloads []string, n int) []string {
	if n >= len(payloads) {
		return payloads
	}

	// Simple sampling: take first N
	// For production, use proper random sampling
	return payloads[:n]
}
