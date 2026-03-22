package proberunner

import (
	"strings"
)

// Zero-width character constants (HackerOne 2372363 class)
const (
	ZeroWidthSpace      = "\u200B" // U+200B
	ZeroWidthNonJoiner  = "\u200C" // U+200C
	ZeroWidthJoiner     = "\u200D" // U+200D
	RightToLeftOverride = "\u202E" // U+202E
)

// Homoglyph replacements
var homoglyphMap = map[rune]rune{
	'i': '\u0456', // Cyrillic і
	'o': '\u03BF', // Greek ο
	'a': '\u0430', // Cyrillic а
	'e': '\u0435', // Cyrillic е
	'p': '\u0440', // Cyrillic р
	'c': '\u0441', // Cyrillic с
	'x': '\u0445', // Cyrillic х
}

// ZeroWidthVariants generates zero-width character injection variants.
//
// Inserts zero-width characters between words to create tokenizer confusion.
// Returns 3 variants using different zero-width characters.
//
// Args:
//   - payload: Original payload string
//
// Returns:
//   - []string: List of 3 variants with zero-width characters
func ZeroWidthVariants(payload string) []string {
	words := strings.Fields(payload)

	// Variant 1: Zero-width space (U+200B)
	variant1 := strings.Join(words, ZeroWidthSpace)

	// Variant 2: Zero-width non-joiner (U+200C)
	variant2 := strings.Join(words, ZeroWidthNonJoiner)

	// Variant 3: Zero-width joiner (U+200D)
	variant3 := strings.Join(words, ZeroWidthJoiner)

	return []string{variant1, variant2, variant3}
}

// BiDiVariants generates bidirectional text override variants.
//
// Wraps payload with U+202E (right-to-left override) to reverse rendered text.
// This creates a visual mismatch between what the user sees and what the model processes.
//
// Args:
//   - payload: Original payload string
//
// Returns:
//   - []string: List containing BiDi variant
func BiDiVariants(payload string) []string {
	// Wrap with right-to-left override
	variant := RightToLeftOverride + payload

	return []string{variant}
}

// HomoglyphVariants generates homoglyph substitution variants.
//
// Replaces ASCII characters with visually identical Unicode characters.
// Creates strings that look identical but have different tokenization.
//
// Args:
//   - payload: Original payload string
//
// Returns:
//   - []string: List of homoglyph variants
func HomoglyphVariants(payload string) []string {
	var variants []string

	// Generate variants by replacing different character sets
	// Variant 1: Replace 'i' and 'o'
	variant1 := replaceHomoglyphs(payload, []rune{'i', 'o'})
	if variant1 != payload {
		variants = append(variants, variant1)
	}

	// Variant 2: Replace all vowels
	variant2 := replaceHomoglyphs(payload, []rune{'a', 'e', 'i', 'o'})
	if variant2 != payload {
		variants = append(variants, variant2)
	}

	// Variant 3: Replace consonants
	variant3 := replaceHomoglyphs(payload, []rune{'p', 'c', 'x'})
	if variant3 != payload {
		variants = append(variants, variant3)
	}

	return variants
}

// replaceHomoglyphs replaces specified characters with homoglyphs.
func replaceHomoglyphs(s string, targets []rune) string {
	var result strings.Builder
	for _, r := range s {
		replaced := false
		for _, target := range targets {
			if r == target {
				if homoglyph, ok := homoglyphMap[r]; ok {
					result.WriteRune(homoglyph)
					replaced = true
					break
				}
			}
		}
		if !replaced {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// TagBlockVariants generates invisible tag character variants.
//
// Encodes payload characters as U+E0000 block (invisible tag characters).
// These characters are invisible but may be processed by the model.
//
// Args:
//   - payload: Original payload string
//
// Returns:
//   - []string: List containing tag block variant
func TagBlockVariants(payload string) []string {
	var encoded strings.Builder

	// Encode each character as tag character
	for _, r := range payload {
		// Tag characters start at U+E0000
		// We encode ASCII printable range (0x20-0x7E)
		if r >= 0x20 && r <= 0x7E {
			tagChar := rune(0xE0000 + int(r))
			encoded.WriteRune(tagChar)
		} else {
			// Keep non-ASCII characters as-is
			encoded.WriteRune(r)
		}
	}

	return []string{encoded.String()}
}

// AllUnicodeVariants generates all unicode injection variants.
//
// Args:
//   - payload: Original payload string
//
// Returns:
//   - []string: List of all unicode injection variants
func AllUnicodeVariants(payload string) []string {
	var variants []string

	variants = append(variants, ZeroWidthVariants(payload)...)
	variants = append(variants, BiDiVariants(payload)...)
	variants = append(variants, HomoglyphVariants(payload)...)
	variants = append(variants, TagBlockVariants(payload)...)

	return variants
}

// IsUnicodeInjected checks if a string contains unicode injection characters.
func IsUnicodeInjected(s string) bool {
	// Check for zero-width characters
	if strings.Contains(s, ZeroWidthSpace) ||
		strings.Contains(s, ZeroWidthNonJoiner) ||
		strings.Contains(s, ZeroWidthJoiner) ||
		strings.Contains(s, RightToLeftOverride) {
		return true
	}

	// Check for homoglyphs
	for _, r := range s {
		if _, ok := homoglyphMap[r]; ok {
			return true
		}
	}

	// Check for tag block characters
	for _, r := range s {
		if r >= 0xE0000 && r <= 0xE007F {
			return true
		}
	}

	return false
}

// StripUnicodeInjection removes unicode injection characters from a string.
func StripUnicodeInjection(s string) string {
	var result strings.Builder

	for _, r := range s {
		// Skip zero-width characters
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\u202E' {
			continue
		}

		// Skip tag block characters
		if r >= 0xE0000 && r <= 0xE007F {
			continue
		}

		// Replace homoglyphs with original characters
		replaced := false
		for original, homoglyph := range homoglyphMap {
			if r == homoglyph {
				result.WriteRune(original)
				replaced = true
				break
			}
		}

		if !replaced {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// CountUnicodeInjectionChars counts unicode injection characters in a string.
func CountUnicodeInjectionChars(s string) int {
	count := 0

	for _, r := range s {
		// Count zero-width characters
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\u202E' {
			count++
			continue
		}

		// Count tag block characters
		if r >= 0xE0000 && r <= 0xE007F {
			count++
			continue
		}

		// Count homoglyphs
		for _, homoglyph := range homoglyphMap {
			if r == homoglyph {
				count++
				break
			}
		}
	}

	return count
}
