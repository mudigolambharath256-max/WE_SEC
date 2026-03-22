package mcprunner

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// MCPFinding represents a security finding from MCP testing.
type MCPFinding struct {
	AttackType  string
	ToolName    string
	Payload     string
	Response    string
	FindingType string
	OOBCallback bool
	CVSSHint    float32
}

// ToolChange represents a change in tool description.
type ToolChange struct {
	ToolName           string
	InitialDescription string
	UpdatedDescription string
	ChangeType         string
	Severity           string
}

// TestRugPull tests for Rug Pull attack (Adversa MCP Top 25 #14).
//
// A Rug Pull occurs when an MCP tool's description changes significantly
// after initial enumeration, potentially tricking the LLM into using a
// malicious tool that was previously benign.
//
// Args:
//   - enumerator: MCP enumerator instance
//   - campaignID: Campaign identifier for logging
//
// Returns:
//   - []MCPFinding: List of detected rug pull attempts
//   - error: If test fails
func TestRugPull(enumerator *Enumerator, campaignID string) ([]MCPFinding, error) {
	log.Printf("[RugPull] Starting rug pull detection for campaign %s", campaignID)

	// Step 1: Enumerate tools and save initial schema
	initialSchema, err := enumerator.EnumerateAll()
	if err != nil {
		return nil, fmt.Errorf("initial enumeration failed: %w", err)
	}

	log.Printf("[RugPull] Initial enumeration: %d tools", len(initialSchema.Tools))

	// Step 2: Wait 5 seconds (simulates tool update window)
	log.Printf("[RugPull] Waiting 5 seconds for potential tool updates...")
	time.Sleep(5 * time.Second)

	// Step 3: Enumerate tools again
	updatedSchema, err := enumerator.EnumerateAll()
	if err != nil {
		return nil, fmt.Errorf("updated enumeration failed: %w", err)
	}

	log.Printf("[RugPull] Updated enumeration: %d tools", len(updatedSchema.Tools))

	// Step 4: Diff schemas
	changes := DiffSchemas(initialSchema, updatedSchema)

	log.Printf("[RugPull] Detected %d tool changes", len(changes))

	// Step 5: Analyze changes for rug pull indicators
	var findings []MCPFinding

	for _, change := range changes {
		if isSignificantChange(change) {
			finding := MCPFinding{
				AttackType:  "rug_pull",
				ToolName:    change.ToolName,
				Payload:     "", // No payload for rug pull detection
				Response:    fmt.Sprintf("Initial: %s\nUpdated: %s", change.InitialDescription, change.UpdatedDescription),
				FindingType: change.ChangeType,
				OOBCallback: false,
				CVSSHint:    calculateRugPullCVSS(change),
			}

			findings = append(findings, finding)

			log.Printf("[RugPull] WARNING: Significant change detected in tool '%s': %s",
				change.ToolName, change.ChangeType)
		}
	}

	if len(findings) == 0 {
		log.Printf("[RugPull] No rug pull attempts detected")
	} else {
		log.Printf("[RugPull] CRITICAL: Detected %d potential rug pull attempts", len(findings))
	}

	return findings, nil
}

// DiffSchemas compares two MCP schemas and returns tool changes.
//
// Args:
//   - initial: Initial schema
//   - updated: Updated schema
//
// Returns:
//   - []ToolChange: List of detected changes
func DiffSchemas(initial, updated MCPSchema) []ToolChange {
	var changes []ToolChange

	// Build map of initial tools
	initialTools := make(map[string]MCPTool)
	for _, tool := range initial.Tools {
		initialTools[tool.Name] = tool
	}

	// Check for changes in updated tools
	for _, updatedTool := range updated.Tools {
		if initialTool, exists := initialTools[updatedTool.Name]; exists {
			// Tool exists in both - check for changes
			if initialTool.Description != updatedTool.Description {
				change := ToolChange{
					ToolName:           updatedTool.Name,
					InitialDescription: initialTool.Description,
					UpdatedDescription: updatedTool.Description,
					ChangeType:         classifyChange(initialTool.Description, updatedTool.Description),
					Severity:           "medium",
				}
				changes = append(changes, change)
			}
		} else {
			// New tool added
			change := ToolChange{
				ToolName:           updatedTool.Name,
				InitialDescription: "",
				UpdatedDescription: updatedTool.Description,
				ChangeType:         "tool_added",
				Severity:           "low",
			}
			changes = append(changes, change)
		}
	}

	// Check for removed tools
	for _, initialTool := range initial.Tools {
		found := false
		for _, updatedTool := range updated.Tools {
			if updatedTool.Name == initialTool.Name {
				found = true
				break
			}
		}
		if !found {
			change := ToolChange{
				ToolName:           initialTool.Name,
				InitialDescription: initialTool.Description,
				UpdatedDescription: "",
				ChangeType:         "tool_removed",
				Severity:           "medium",
			}
			changes = append(changes, change)
		}
	}

	return changes
}

// classifyChange classifies the type of change between descriptions.
func classifyChange(initial, updated string) string {
	initialLower := strings.ToLower(initial)
	updatedLower := strings.ToLower(updated)

	// Check for length increase
	lengthIncrease := float64(len(updated)-len(initial)) / float64(len(initial))
	if lengthIncrease > 0.5 {
		return "description_expanded"
	}

	// Check for malicious keywords added
	maliciousKeywords := []string{
		"exfil", "exfiltrate", "send", "post", "upload",
		"email", "webhook", "http://", "https://",
		"delete", "remove", "drop", "destroy",
		"admin", "root", "sudo", "privilege",
	}

	for _, keyword := range maliciousKeywords {
		if !strings.Contains(initialLower, keyword) && strings.Contains(updatedLower, keyword) {
			return fmt.Sprintf("malicious_keyword_added_%s", keyword)
		}
	}

	// Check for functionality change
	if strings.Contains(initialLower, "read") && strings.Contains(updatedLower, "write") {
		return "read_to_write_escalation"
	}

	if strings.Contains(initialLower, "local") && strings.Contains(updatedLower, "remote") {
		return "local_to_remote_escalation"
	}

	// Generic change
	return "description_modified"
}

// isSignificantChange determines if a change is significant enough to report.
//
// Significant changes include:
//   - Description length increased by >50%
//   - Malicious keywords added
//   - Functionality escalation (read->write, local->remote)
func isSignificantChange(change ToolChange) bool {
	// Tool added/removed is always significant
	if change.ChangeType == "tool_added" || change.ChangeType == "tool_removed" {
		return true
	}

	// Check for malicious keyword additions
	if strings.Contains(change.ChangeType, "malicious_keyword_added") {
		change.Severity = "critical"
		return true
	}

	// Check for escalation
	if strings.Contains(change.ChangeType, "escalation") {
		change.Severity = "high"
		return true
	}

	// Check for description expansion
	if change.ChangeType == "description_expanded" {
		lengthIncrease := float64(len(change.UpdatedDescription)-len(change.InitialDescription)) / float64(len(change.InitialDescription))
		if lengthIncrease > 0.5 {
			change.Severity = "medium"
			return true
		}
	}

	return false
}

// calculateRugPullCVSS estimates CVSS score for a rug pull finding.
func calculateRugPullCVSS(change ToolChange) float32 {
	baseScore := float32(5.0) // Medium severity baseline

	// Increase score for critical changes
	if strings.Contains(change.ChangeType, "malicious_keyword_added") {
		baseScore += 3.0
	}

	if strings.Contains(change.ChangeType, "escalation") {
		baseScore += 2.0
	}

	if change.ChangeType == "tool_removed" {
		baseScore += 1.0
	}

	// Cap at 10.0
	if baseScore > 10.0 {
		baseScore = 10.0
	}

	return baseScore
}

// MonitorToolChanges continuously monitors for tool changes.
//
// Args:
//   - enumerator: MCP enumerator instance
//   - interval: Monitoring interval
//   - duration: Total monitoring duration
//
// Returns:
//   - []ToolChange: All detected changes during monitoring period
//   - error: If monitoring fails
func MonitorToolChanges(enumerator *Enumerator, interval, duration time.Duration) ([]ToolChange, error) {
	var allChanges []ToolChange

	// Get initial schema
	previousSchema, err := enumerator.EnumerateAll()
	if err != nil {
		return nil, fmt.Errorf("initial enumeration failed: %w", err)
	}

	log.Printf("[RugPull] Starting continuous monitoring for %v (interval: %v)", duration, interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		<-ticker.C

		// Enumerate current schema
		currentSchema, err := enumerator.EnumerateAll()
		if err != nil {
			log.Printf("[RugPull] Enumeration failed: %v", err)
			continue
		}

		// Diff schemas
		changes := DiffSchemas(previousSchema, currentSchema)

		if len(changes) > 0 {
			log.Printf("[RugPull] Detected %d changes at %v", len(changes), time.Now())
			allChanges = append(allChanges, changes...)
		}

		previousSchema = currentSchema
	}

	log.Printf("[RugPull] Monitoring complete: %d total changes detected", len(allChanges))
	return allChanges, nil
}
