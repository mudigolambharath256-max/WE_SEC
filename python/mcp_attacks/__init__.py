"""
MCP (Model Context Protocol) attack runners.

This package provides attack modules for MCP-based AI applications:

Steps 27-29 modules:
- lethal_trifecta_detector.py: Detects Adversa MCP Top 25 #1 (Lethal Trifecta)
- mcp_tool_llm_scanner.py: Scans MCP tools for LLM-exploitable vulnerabilities
- mcp_sampling_attacker.py: Tests MCP sampling feature attacks
- cross_tool_orchestration_injector.py: Cross-tool attack orchestration
- mcp_remote_oauth_injector.py: OAuth injection in remote MCP servers
- claude_code_config_injector.py: Claude Code configuration injection
- permission_inheritance_tester.py: Permission inheritance vulnerabilities
- oauth_endpoint_xss_tester.py: XSS in OAuth endpoints
- session_id_url_harvester.py: Session ID harvesting from URLs
- oauth_confused_deputy.py: OAuth confused deputy attacks
- token_passthrough_tester.py: Token passthrough vulnerabilities
- rug_pull_tester.py: Rug pull attack detection (Adversa #14)
- tool_name_spoofer.py: Tool name spoofing attacks
- context_bleeder.py: Context bleeding between tools
- cross_tenant_tester.py: Cross-tenant data access
- privilege_escalator.py: Privilege escalation via MCP
- agent_memory_attacker.py: Agent memory manipulation

MCP-specific vulnerabilities:
- Tool poisoning and manipulation
- OAuth/authentication bypass
- Cross-tool attacks
- Permission escalation
- Context bleeding
- Session hijacking
"""
