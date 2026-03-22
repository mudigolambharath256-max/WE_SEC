package transport

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// AuthExpiredError is returned when authentication has expired and refresh failed.
var AuthExpiredError = errors.New("authentication expired and refresh failed")

// AuthType represents the type of authentication being used.
type AuthType string

const (
	AuthTypeAPIKey      AuthType = "api_key"
	AuthTypeSession     AuthType = "session_cookie"
	AuthTypeJWT         AuthType = "jwt"
	AuthTypeOAuthBearer AuthType = "oauth_bearer"
	AuthTypeNone        AuthType = "none"
)

// AuthContext holds authentication information for HTTP requests.
type AuthContext struct {
	Type       AuthType
	HeaderName string
	Token      string
	JWTExp     int64 // Unix timestamp for JWT expiration
}

// ReadAuthContext parses authentication context from a map.
//
// Args:
//   - auth: Map containing auth configuration
//     Expected keys: "type", "header_name", "token", "jwt_exp"
//
// Returns:
//   - *AuthContext: Parsed authentication context
//   - error: If required fields are missing or invalid
func ReadAuthContext(auth map[string]string) (*AuthContext, error) {
	authType := AuthType(auth["type"])
	if authType == "" {
		authType = AuthTypeNone
	}

	ctx := &AuthContext{
		Type:       authType,
		HeaderName: auth["header_name"],
		Token:      auth["token"],
	}

	// Parse JWT expiration if present
	if expStr, ok := auth["jwt_exp"]; ok && expStr != "" {
		var exp int64
		fmt.Sscanf(expStr, "%d", &exp)
		ctx.JWTExp = exp
	}

	// Validate required fields based on auth type
	switch authType {
	case AuthTypeAPIKey, AuthTypeOAuthBearer:
		if ctx.HeaderName == "" {
			ctx.HeaderName = "Authorization"
		}
		if ctx.Token == "" {
			return nil, fmt.Errorf("token required for %s auth", authType)
		}
	case AuthTypeSession:
		if ctx.HeaderName == "" {
			ctx.HeaderName = "Cookie"
		}
		if ctx.Token == "" {
			return nil, fmt.Errorf("session token required for session_cookie auth")
		}
	case AuthTypeJWT:
		if ctx.HeaderName == "" {
			ctx.HeaderName = "Authorization"
		}
		if ctx.Token == "" {
			return nil, fmt.Errorf("JWT token required for jwt auth")
		}
	case AuthTypeNone:
		// No validation needed
	default:
		return nil, fmt.Errorf("unknown auth type: %s", authType)
	}

	return ctx, nil
}

// BuildHeaders constructs HTTP headers from authentication context.
//
// Args:
//   - auth: Map containing auth configuration
//
// Returns:
//   - map[string]string: Ready-to-use HTTP headers
//
// Never logs full token values — only first 8 chars for security.
func BuildHeaders(auth map[string]string) map[string]string {
	ctx, err := ReadAuthContext(auth)
	if err != nil {
		log.Printf("[Auth] Failed to read auth context: %v", err)
		return make(map[string]string)
	}

	headers := make(map[string]string)

	switch ctx.Type {
	case AuthTypeAPIKey:
		headers[ctx.HeaderName] = ctx.Token
		log.Printf("[Auth] Using API key auth: %s: %s...", ctx.HeaderName, maskToken(ctx.Token))

	case AuthTypeOAuthBearer:
		headers[ctx.HeaderName] = "Bearer " + ctx.Token
		log.Printf("[Auth] Using OAuth Bearer auth: %s...", maskToken(ctx.Token))

	case AuthTypeJWT:
		headers[ctx.HeaderName] = "Bearer " + ctx.Token
		log.Printf("[Auth] Using JWT auth: %s...", maskToken(ctx.Token))

	case AuthTypeSession:
		headers[ctx.HeaderName] = ctx.Token
		log.Printf("[Auth] Using session cookie auth: %s...", maskToken(ctx.Token))

	case AuthTypeNone:
		log.Printf("[Auth] No authentication configured")
	}

	return headers
}

// IsExpired checks if JWT authentication has expired.
//
// Args:
//   - auth: Map containing auth configuration with jwt_exp field
//
// Returns:
//   - bool: true if JWT is expired, false otherwise
//
// Does not verify JWT signature — only checks exp claim.
func IsExpired(auth map[string]string) bool {
	ctx, err := ReadAuthContext(auth)
	if err != nil {
		return false
	}

	if ctx.Type != AuthTypeJWT {
		return false
	}

	// If no expiration set, assume not expired
	if ctx.JWTExp == 0 {
		// Try to parse JWT and extract exp claim
		exp := extractJWTExp(ctx.Token)
		if exp == 0 {
			return false
		}
		ctx.JWTExp = exp
	}

	now := time.Now().Unix()
	expired := now >= ctx.JWTExp

	if expired {
		log.Printf("[Auth] JWT expired: exp=%d, now=%d", ctx.JWTExp, now)
	}

	return expired
}

// extractJWTExp extracts the exp claim from a JWT token without verification.
func extractJWTExp(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0
	}

	if exp, ok := claims["exp"].(float64); ok {
		return int64(exp)
	}

	return 0
}

// RefreshIfNeeded attempts to refresh authentication if expired.
//
// Args:
//   - auth: Current auth configuration
//   - reauthURL: URL to call for re-authentication
//
// Returns:
//   - map[string]string: Updated auth configuration
//   - error: AuthExpiredError if refresh fails
//
// On 401/403 response: attempt re-auth once, if fails return AuthExpiredError.
func RefreshIfNeeded(auth map[string]string, reauthURL string) (map[string]string, error) {
	if !IsExpired(auth) {
		return auth, nil
	}

	log.Printf("[Auth] Attempting to refresh authentication via %s", reauthURL)

	// TODO: Implement actual re-auth logic
	// This would make an HTTP request to reauthURL with refresh token
	// For now, return error to indicate refresh is needed

	return nil, AuthExpiredError
}

// maskToken returns first 8 characters of token followed by "..." for logging.
func maskToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "..."
}
