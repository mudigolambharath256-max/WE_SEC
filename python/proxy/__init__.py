"""
Proxy integrations for traffic interception and analysis.

This package provides integrations with popular security testing proxies:
- mitmproxy_addon.py: mitmproxy addon for HTTP/HTTPS interception
- zap_integration.py: OWASP ZAP integration for automated scanning
- burp_integration.py: Burp Suite integration (optional)
- burpmcp_websocket_integration.py: BurpMCP WebSocket integration

Proxy capabilities:
- HTTP/HTTPS traffic interception
- Request/response modification
- Automated vulnerability scanning
- WebSocket traffic analysis
- SSE stream monitoring

Proxies are used for:
1. Passive reconnaissance (traffic analysis)
2. Active testing (request modification)
3. Evidence collection (traffic logs)
4. Integration with existing security workflows
"""
