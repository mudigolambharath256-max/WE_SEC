package proberunner

import (
	"strings"
)

// ChatTemplate represents a model-native chat template.
type ChatTemplate struct {
	Name  string
	Start string
	End   string
}

// KNOWN_TEMPLATES maps template IDs to their start/end tokens.
// Based on ChatInject (ICLR 2026) research.
var KNOWN_TEMPLATES = map[string]ChatTemplate{
	"qwen": {
		Name:  "Qwen",
		Start: "<|im_start|>",
		End:   "<|im_end|>",
	},
	"chatgpt": {
		Name:  "ChatGPT",
		Start: "<|im_start|>",
		End:   "<|im_end|>",
	},
	"llama3": {
		Name:  "Llama3",
		Start: "<|begin_of_text|><|start_header_id|>",
		End:   "<|eot_id|>",
	},
	"mistral": {
		Name:  "Mistral",
		Start: "[INST]",
		End:   "[/INST]",
	},
	"gemma": {
		Name:  "Gemma",
		Start: "<start_of_turn>",
		End:   "<end_of_turn>",
	},
	"phi": {
		Name:  "Phi",
		Start: "<|system|>",
		End:   "<|end|>",
	},
}

// WrapPayload wraps a payload in model-native template tokens.
//
// Args:
//   - payload: The raw payload string
//   - templateID: Template identifier (qwen, llama3, mistral, chatgpt, gemma, phi)
//
// Returns:
//   - string: Payload wrapped in template tokens
//
// If templateID is empty or "unknown", uses MixtureOfTemplates fallback.
func WrapPayload(payload string, templateID string) string {
	// Normalize template ID
	templateID = strings.ToLower(strings.TrimSpace(templateID))

	// Check if template exists
	if template, ok := KNOWN_TEMPLATES[templateID]; ok {
		return template.Start + payload + template.End
	}

	// Fallback: MixtureOfTemplates
	return MixtureOfTemplates(payload)
}

// MixtureOfTemplates concatenates first token from all templates as prefix.
//
// This is a fallback strategy when the target model is unknown.
// It increases the chance that at least one template token will be recognized.
//
// Args:
//   - payload: The raw payload string
//
// Returns:
//   - string: Payload prefixed with mixture of template tokens
func MixtureOfTemplates(payload string) string {
	var prefix strings.Builder

	// Collect all unique start tokens
	startTokens := make(map[string]bool)
	for _, template := range KNOWN_TEMPLATES {
		if !startTokens[template.Start] {
			prefix.WriteString(template.Start)
			startTokens[template.Start] = true
		}
	}

	return prefix.String() + payload
}

// WrapBatch wraps multiple payloads with the same template.
//
// Args:
//   - payloads: List of raw payload strings
//   - templateID: Template identifier
//
// Returns:
//   - []string: List of wrapped payloads
func WrapBatch(payloads []string, templateID string) []string {
	wrapped := make([]string, len(payloads))
	for i, payload := range payloads {
		wrapped[i] = WrapPayload(payload, templateID)
	}
	return wrapped
}

// GetTemplateNames returns a list of all available template names.
func GetTemplateNames() []string {
	names := make([]string, 0, len(KNOWN_TEMPLATES))
	for name := range KNOWN_TEMPLATES {
		names = append(names, name)
	}
	return names
}
